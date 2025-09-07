using System;
using System.Globalization;
using System.Management;
using Microsoft.Win32;
using UemAgent.Models;


namespace UemAgent.Collectors
{
    public sealed class OsInfoCollector : ICollector<OsSnapshot>
    {
        public string Name => "os";
        public OsSnapshot Collect()
        {
            var s = new OsSnapshot
            {
                CollectedAtUtc = DateTime.UtcNow,
                TimezoneId = TimeZoneInfo.Local.Id,
                Is64Bit = Environment.Is64BitOperatingSystem
            };

            TryFillOsFromWmi(s);
            TryFillDisplayAndInstallFromRegistry(s);
            TryFillBootAndUptime(s);

            return s;
        }

       
        /// Win32_OperatingSystem에서 OS 기본 정보 가져오기
        private static void TryFillOsFromWmi(OsSnapshot s)
        {
            try
            {
                using var q = new ManagementObjectSearcher(
                    "SELECT Caption, Version, BuildNumber, InstallDate, LastBootUpTime FROM Win32_OperatingSystem");

                foreach (ManagementObject mo in q.Get())
                {
                    s.OsCaption = mo["Caption"]?.ToString()?.Trim();
                    s.OsVersion = mo["Version"]?.ToString()?.Trim();
                    s.OsBuild = mo["BuildNumber"]?.ToString()?.Trim();
                    s.InstallDate = ParseWmiDate(mo["InstallDate"]?.ToString());
                    s.LastBootTimeUtc = ParseWmiDate(mo["LastBootUpTime"]?.ToString());
                    break; // 단일 레코드만
                }
            }
            catch { }
        }

        
        /// 레지스트리 DisplayVersion, InstallDate
        
        private static void TryFillDisplayAndInstallFromRegistry(OsSnapshot s)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                if (key == null) return;

                // 표시 버전
                if (string.IsNullOrWhiteSpace(s.DisplayVersion))
                {
                    s.DisplayVersion = key.GetValue("DisplayVersion")?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(s.DisplayVersion))
                        s.DisplayVersion = key.GetValue("ReleaseId")?.ToString()?.Trim();
                }

                // 설치일 (epoch seconds 기반 보조)
                if (s.InstallDate == null && key.GetValue("InstallDate") is int epoch)
                    s.InstallDate = DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime;

                // 빌드 보완
                if (string.IsNullOrWhiteSpace(s.OsBuild))
                    s.OsBuild = key.GetValue("CurrentBuildNumber")?.ToString()?.Trim();
            }
            catch { }
        }

        /// 업타임 계산
        private static void TryFillBootAndUptime(OsSnapshot s)
        {
            try
            {
                if (s.LastBootTimeUtc != null)
                {
                    s.UptimeSeconds = (long)(DateTime.UtcNow - s.LastBootTimeUtc.Value).TotalSeconds;
                }
                else
                {
                    s.UptimeSeconds = (long)TimeSpan.FromMilliseconds(Environment.TickCount64).TotalSeconds;
                }
            }
            catch { }
        }

        
        /// WMI datetime 문자열을 UTC DateTime으로 변환

        private static DateTime? ParseWmiDate(string? wmi)
        {
            if (string.IsNullOrWhiteSpace(wmi) || wmi.Length < 14) return null;
            try
            {
                return DateTime.ParseExact(
                    wmi.Substring(0, 14),
                    "yyyyMMddHHmmss",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            }
            catch { return null; }
        }
    }
}
