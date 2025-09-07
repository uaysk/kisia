using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using UemAgent.Models;

namespace UemAgent.Collectors
{
    public sealed class VmDetector : ICollector<VmSignals>
    {
        private static readonly string[] VmwareOui = { "00:05:69", "00:0C:29", "00:50:56" };
        private static readonly string[] VBoxOui = { "08:00:27" };
        private static readonly string[] HyperVOui = { "00:15:5D" };
        private static readonly string[] ParallelsOui = { "00:1C:42" };
        private static readonly string[] QemuOui = { "52:54:00" };
        private static readonly string[] XenOui = { "00:16:3E" };

        public string Name => "vm";
        public VmSignals Collect()
        {
            var sig = new VmSignals
            {
                HypervisorPresent = CheckHypervisorPresent(),
                WmiHit = CheckWmiForVm(out var v1),
                BiosHit = CheckBiosForVm(out var v2),
                MacOuiHit = CheckMacOui(out var v3),
                ProcessHit = CheckVmProcesses(out var v4),
                DiskHit = CheckDiskForVm(out var v5),
                DriverHit = CheckVmDrivers(out var v6),
                VendorGuess = v1 ?? v2 ?? v3 ?? v4 ?? v5 ?? v6
            };
            return sig;
        }

        // --- Hypervisor 플래그 ---
        private static bool CheckHypervisorPresent()
        {
            try
            {
                using var q = new ManagementObjectSearcher("SELECT HypervisorPresent FROM Win32_ComputerSystem");
                foreach (ManagementObject mo in q.Get())
                    if (mo["HypervisorPresent"] is bool b) return b;
            }
            catch { }
            return false;
        }

        // --- WMI Manufacturer/Model ---
        private static bool CheckWmiForVm(out string? vendor)
        {
            vendor = null;
            try
            {
                using var q = new ManagementObjectSearcher("SELECT Manufacturer, Model FROM Win32_ComputerSystem");
                foreach (ManagementObject mo in q.Get())
                {
                    var manu = (mo["Manufacturer"]?.ToString() ?? "").ToLowerInvariant();
                    var model = (mo["Model"]?.ToString() ?? "").ToLowerInvariant();
                    if (manu.Contains("vmware") || model.Contains("vmware")) { vendor = "vmware"; return true; }
                    if (model.Contains("virtualbox")) { vendor = "virtualbox"; return true; }
                    if (manu.Contains("microsoft") && model.Contains("virtual")) { vendor = "hyperv"; return true; }
                    if (model.Contains("qemu") || model.Contains("kvm")) { vendor = "qemu/kvm"; return true; }
                    if (model.Contains("xen")) { vendor = "xen"; return true; }
                    if (model.Contains("parallels")) { vendor = "parallels"; return true; }
                }
            }
            catch { }
            return false;
        }

        // --- BIOS 버전 문자열 ---
        private static bool CheckBiosForVm(out string? vendor)
        {
            vendor = null;
            try
            {
                using var q = new ManagementObjectSearcher("SELECT SMBIOSBIOSVersion FROM Win32_BIOS");
                foreach (ManagementObject mo in q.Get())
                {
                    var ver = (mo["SMBIOSBIOSVersion"]?.ToString() ?? "").ToLowerInvariant();
                    if (ver.Contains("vmware")) { vendor = "vmware"; return true; }
                    if (ver.Contains("vbox")) { vendor = "virtualbox"; return true; }
                    if (ver.Contains("hyper-v")) { vendor = "hyperv"; return true; }
                    if (ver.Contains("qemu")) { vendor = "qemu/kvm"; return true; }
                    if (ver.Contains("xen")) { vendor = "xen"; return true; }
                    if (ver.Contains("parallels")) { vendor = "parallels"; return true; }
                }
            }
            catch { }
            return false;
        }

        // --- MAC OUI (필터링 안 붙인 기본 버전) ---
        private static bool CheckMacOui(out string? vendor)
        {
            vendor = null;
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    var mac = string.Join(":", nic.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")));
                    if (mac.Length < 8) continue;
                    var prefix = mac[..8].ToUpperInvariant();

                    if (VmwareOui.Contains(prefix)) { vendor = "vmware"; return true; }
                    if (VBoxOui.Contains(prefix)) { vendor = "virtualbox"; return true; }
                    if (HyperVOui.Contains(prefix)) { vendor = "hyperv"; return true; }
                    if (ParallelsOui.Contains(prefix)) { vendor = "parallels"; return true; }
                    if (QemuOui.Contains(prefix)) { vendor = "qemu/kvm"; return true; }
                    if (XenOui.Contains(prefix)) { vendor = "xen"; return true; }
                }
            }
            catch { }
            return false;
        }

        // --- VM 전용 프로세스 ---
        private static bool CheckVmProcesses(out string? vendor)
        {
            vendor = null;
            try
            {
                var names = Process.GetProcesses().Select(p => p.ProcessName.ToLowerInvariant()).ToArray();
                if (names.Any(n => n.Contains("vmtoolsd"))) { vendor = "vmware"; return true; }
                if (names.Any(n => n.Contains("vboxservice") || n.Contains("vboxtray"))) { vendor = "virtualbox"; return true; }
                if (names.Any(n => n.Equals("vmmem"))) { vendor = "hyperv"; return true; }
            }
            catch { }
            return false;
        }

        // --- 디스크 장치 모델 (게스트면 가상 디스크) ---
        private static bool CheckDiskForVm(out string? vendor)
        {
            vendor = null;
            try
            {
                using var q = new ManagementObjectSearcher("SELECT Model FROM Win32_DiskDrive");
                foreach (ManagementObject mo in q.Get())
                {
                    var model = (mo["Model"]?.ToString() ?? "").ToLowerInvariant();
                    if (model.Contains("vmware")) { vendor = "vmware"; return true; }
                    if (model.Contains("vbox")) { vendor = "virtualbox"; return true; }
                    if (model.Contains("virtual")) { vendor = "hyperv/qemu"; return true; }
                }
            }
            catch { }
            return false;
        }

        // --- VM 전용 드라이버 파일 존재 여부 ---
        private static bool CheckVmDrivers(out string? vendor)
        {
            vendor = null;
            try
            {
                string sys32 = Environment.SystemDirectory;
                string[] vmDrivers = {
                    "drivers\\vmhgfs.sys",      // VMware
                    "drivers\\vmmouse.sys",     // VMware
                    "drivers\\VBoxGuest.sys",   // VirtualBox
                    "drivers\\VBoxSF.sys",      // VirtualBox Shared Folders
                };

                foreach (var relPath in vmDrivers)
                {
                    var path = Path.Combine(sys32, relPath);
                    if (File.Exists(path))
                    {
                        if (path.Contains("vm")) vendor = "vmware";
                        if (path.Contains("VBox")) vendor = "virtualbox";
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }
    }
}
