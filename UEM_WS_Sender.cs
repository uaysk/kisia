using System;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace UemAgent.Net
{
    public sealed class UEM_WS_Sender : IAsyncDisposable
    {
        private readonly Uri _endpoint;
        private readonly ClientWebSocket _ws = new ClientWebSocket();

        public UEM_WS_Sender(string endpoint)
        {
            _endpoint = new Uri(endpoint);
        }

        public async Task ConnectAsync()
        {
            await _ws.ConnectAsync(_endpoint, CancellationToken.None);
        }

        public async Task SendJsonAsync(string json)
        {
            var payload = Encoding.UTF8.GetBytes(json);
            await _ws.SendAsync(payload, WebSocketMessageType.Text, true, CancellationToken.None);
        }

        public async ValueTask DisposeAsync()
        {
            if (_ws.State == WebSocketState.Open)
                await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None);
            _ws.Dispose();
        }
    }
}
