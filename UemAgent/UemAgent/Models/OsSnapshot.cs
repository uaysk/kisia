using System.Text.Json.Serialization;

namespace UemAgent.Models
{
    public sealed class OsSnapshot
    {
        // OS
        public string? OsCaption { get; set; }
        public string? OsVersion { get; set; }
        public string? OsBuild { get; set; }
        public string? DisplayVersion { get; set; }
        public DateTime? InstallDate { get; set; }
        public bool Is64Bit { get; set; }

        // Boot
        public DateTime? LastBootTimeUtc { get; set; }
        public long? UptimeSeconds { get; set; }

        // Meta
        public string TimezoneId { get; set; } = TimeZoneInfo.Local.Id;
        public DateTime CollectedAtUtc { get; set; } = DateTime.UtcNow;
    }
}
