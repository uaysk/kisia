using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using UemAgent.Collectors;
using UemAgent.Models;
using UemAgent.Net;

namespace UemAgent.Transport
{
    public sealed class AgentTriggerServer : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly UemUploader _uploader;
        private readonly string _agentId;
        private CancellationTokenSource? _cts;

        public AgentTriggerServer(
            string[] prefixes,                // 아직 미구현: 실제 에이전트가 열 포트/주소 정해야 함 (예: http://+:7070/)
            string serverBaseUrl,             // 아직 미구현: 실제 서버 주소 정해야 함
            string uploadPath = "/api/uem-data", // 아직 미구현: 서버 업로드 엔드포인트 정해야 함
            string? apiKey = null,
            string agentId = "agent-001")
        {
            foreach (var p in prefixes) _listener.Prefixes.Add(p);
            _uploader = new UemUploader(serverBaseUrl, uploadPath, apiKey);
            _agentId = agentId;
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _listener.Start();
            _ = Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        public void Stop()
        {
            _cts?.Cancel();
            _listener.Stop();
        }

        public void Dispose()
        {
            Stop();
            _listener.Close();
            _cts?.Dispose();
        }

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync(); }
                catch when (ct.IsCancellationRequested) { break; }
                catch { continue; }

                _ = Task.Run(() => HandleAsync(ctx), ct);
            }
        }

        private async Task HandleAsync(HttpListenerContext ctx)
        {
            try
            {
                if (ctx.Request.HttpMethod != "POST" || ctx.Request.Url is null || ctx.Request.Url.AbsolutePath != "/collect-now")
                {
                    ctx.Response.StatusCode = (int)HttpStatusCode.NotFound;
                    ctx.Response.Close();
                    return;
                }

                string? commandId = ctx.Request.Headers["x-command-id"];
                string? body = null;
                using (var sr = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding))
                    body = await sr.ReadToEndAsync();

                string? overrideUploadPath = null;
                try
                {
                    if (!string.IsNullOrWhiteSpace(body))
                    {
                        var obj = JsonSerializer.Deserialize<TriggerBody>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        if (!string.IsNullOrWhiteSpace(obj?.CommandId)) commandId = obj!.CommandId;
                        if (!string.IsNullOrWhiteSpace(obj?.UploadPath)) overrideUploadPath = obj!.UploadPath; // 아직 미구현: 서버가 업로드 경로 동적으로 줄 경우 처리 필요
                    }
                }
                catch { }

                var os = new OsInfoCollector().Collect();
                os.Vm = VmDetector.Detect();
                os.Av = AvDetector.Detect();

                var ok = await _uploader.UploadAsync(os, commandId ?? Guid.NewGuid().ToString());
                ctx.Response.StatusCode = ok ? (int)HttpStatusCode.OK : (int)HttpStatusCode.InternalServerError;
                ctx.Response.Close();
            }
            catch
            {
                ctx.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                ctx.Response.Close();
            }
        }

        private sealed class TriggerBody
        {
            public string? CommandId { get; set; }
            public string? UploadPath { get; set; }
        }
    }
}
