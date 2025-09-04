using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using UemAgent.Models;

namespace UemAgent.Collectors
{
    public static class AvDetector
    {
        public static AvSignals Detect()
        {
            var sig = new AvSignals
            {
                DefenderServiceRunning = IsServiceRunning("WinDefend"),
                SecurityHealthRunning = IsServiceRunning("SecurityHealthService")
            };

            // WSC에서 설치된 AV 조회 Defender, Alyac, V3만
            var wscProducts = QueryAntiVirusProducts();
            sig.Products.AddRange(wscProducts);

            // 실행 여부 추정 (프로세스, 서비스 이름 기반)
            var procNames = Process.GetProcesses().Select(p => SafeLower(p.ProcessName)).ToHashSet();
            var runningServices = ServiceController.GetServices()
                                .Where(s => s.Status == ServiceControllerStatus.Running)
                                .SelectMany(s => new[] { SafeLower(s.ServiceName), SafeLower(s.DisplayName) })
                                .ToHashSet();

            foreach (var p in sig.Products)
            {
                var (procKeys, svcKeys) = GetVendorKeywords(p.VendorGuess);

                p.ProcessObserved = procKeys.Any(k => procNames.Contains(k) || procNames.Any(n => n.Contains(k)));
                p.ServiceObserved = svcKeys.Any(k => runningServices.Contains(k) || runningServices.Any(n => n.Contains(k)));
            }

            sig.AvPresent = sig.Products.Count > 0 || sig.DefenderServiceRunning;
            return sig;
        }

        private static List<AvProduct> QueryAntiVirusProducts()
        {
            var list = new List<AvProduct>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\SecurityCenter2",
                    "SELECT displayName, productState FROM AntiVirusProduct");

                foreach (ManagementObject mo in searcher.Get())
                {
                    var name = mo["displayName"]?.ToString() ?? "";
                    var vendor = GuessVendor(name);
                    if (vendor == null) continue; // Defender, Alyac, V3 외에는 무시

                    uint? state = null;
                    try { if (mo["productState"] != null) state = Convert.ToUInt32(mo["productState"]); } catch { }

                    list.Add(new AvProduct
                    {
                        Name = name,               // 직렬화 전에 영어화 후처리
                        VendorGuess = vendor,      // 내부 처리용 (JSON 직렬화 제외됨)
                        ProductStateRaw = state
                    });
                }
            }
            catch
            {
                // 접근이 안되는 일부 환경 무시
            }

            return list;
        }

        private static bool IsServiceRunning(string serviceName)
        {
            try { using var sc = new ServiceController(serviceName); return sc.Status == ServiceControllerStatus.Running; }
            catch { return false; }
        }

        private static string SafeLower(string? s) => (s ?? string.Empty).ToLowerInvariant();

        // Vender태그
        private static string? GuessVendor(string name)
        {
            var n = SafeLower(name);
            if (n.Contains("microsoft") || n.Contains("defender") || n.Contains("windows")) return "microsoft-defender";
            if (n.Contains("alyac") || n.Contains("알약")) return "alyac";
            if (n.Contains("v3") || n.Contains("ahnlab")) return "v3";
            return null;
        }

        // Vender별 프로세스/서비스 키워드
        private static (string[] procKeys, string[] svcKeys) GetVendorKeywords(string? vendor) =>
            vendor switch
            {
                "microsoft-defender" => (new[] { "msmpeng" }, new[] { "windefend" }),
                "alyac" => (new[] { "alyac", "estsecurity" }, new[] { "alyac", "estsecurity" }),
                "v3" => (new[] { "v3", "ahnlab" }, new[] { "v3", "ahnlab" }),
                _ => (Array.Empty<string>(), Array.Empty<string>())
            };
    }
}
