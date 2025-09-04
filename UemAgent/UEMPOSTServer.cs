using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UemAgent.Models;

namespace UemAgent.Net
{
    public sealed class UemUploader
    {
        private readonly HttpClient _http;
        private readonly string _uploadPath;
        private readonly JsonSerializerOptions _jsonOptions;

        public UemUploader(
            string serverBaseUrl,                 // 아직 미구현: 실제 서버 주소 정해야 함
            string uploadPath = "/api/uem-data",  // 아직 미구현: 서버 업로드 엔드포인트 정해야 함
            string? apiKey = null)
        {
            _http = new HttpClient { BaseAddress = new Uri(serverBaseUrl), Timeout = TimeSpan.FromSeconds(15) };
            if (!string.IsNullOrWhiteSpace(apiKey))
                _http.DefaultRequestHeaders.Add("x-api-key", apiKey);
            _uploadPath = uploadPath;
            _jsonOptions = new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                WriteIndented = false
            };
        }

        public async Task<bool> UploadAsync(OsSnapshot snap, string? commandId = null, CancellationToken ct = default)
        {
            if (!string.IsNullOrWhiteSpace(commandId))
            {
                _http.DefaultRequestHeaders.Remove("x-command-id");
                _http.DefaultRequestHeaders.Add("x-command-id", commandId);
            }

            var json = JsonSerializer.Serialize(snap, _jsonOptions);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var res = await _http.PostAsync(_uploadPath, content, ct);
            return res.IsSuccessStatusCode;
        }
    }
}
