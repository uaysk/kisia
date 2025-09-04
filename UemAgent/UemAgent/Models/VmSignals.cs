using System.Text.Json.Serialization;

namespace UemAgent.Models
{
    public sealed class VmSignals
    {
        public bool HypervisorPresent { get; set; }  // Win32_ComputerSystem.HypervisorPresent
        public bool WmiHit { get; set; }             // Manufacturer/Model에 VM 키워드
        public bool BiosHit { get; set; }            // BIOS/BaseBoard에 VM 키워드
        public bool MacOuiHit { get; set; }          // MAC OUI가 VM 벤더 프리픽스
        public bool ProcessHit { get; set; }         // vmtoolsd/VBoxService/vmmem 등 발견
        public bool DiskHit { get; set; }    // 가상 디스크 여부
        public bool DriverHit { get; set; }  // VM 전용 드라이버 발견 여부
        public string? VendorGuess { get; set; }     // vmware/virtualbox/hyperv/qemu/xen/parallels
        
    }
}
