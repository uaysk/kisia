using System.Text.Json.Serialization;

namespace UemAgent.Models
{
    public sealed class AvProduct
    {
        public string Name { get; set; } = "";
        public uint? ProductStateRaw { get; set; }      // WSC 원시값
        public bool? ProcessObserved { get; set; }      // 관련 프로세스 관찰
        public bool? ServiceObserved { get; set; }      // 관련 서비스 관찰

        [JsonIgnore]
        public string? VendorGuess { get; set; }        // microsoft-defender, 알약, v3
    }

    public sealed class AvSignals
    {
        public bool AvPresent { get; set; }
        public bool DefenderServiceRunning { get; set; }
        public bool SecurityHealthRunning { get; set; }
        public List<AvProduct> Products { get; set; } = new();
    }
}
