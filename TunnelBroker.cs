using System.Collections.Concurrent;
using System.Net.WebSockets;
using RDM.Contracts;
namespace RDM.ConnectionServer;
// Relay holds encrypted TLS bytes only, with bounded buffers and no file persistence.
public sealed class TunnelBroker : IDisposable
{
    private sealed class Tunnel(TunnelTicket ticket)
    {
        public TunnelTicket Ticket { get; } = ticket;
        public DateTimeOffset Created { get; } = DateTimeOffset.UtcNow;
        public WebSocket? Manager;
        public WebSocket? Agent;
        public bool ManagerClaimed;
        public bool AgentClaimed;
        public bool Announced;
        public bool Pumping;
        public TaskCompletionSource Done { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
    private readonly ConcurrentDictionary<string,Tunnel> tunnels = new();
    private readonly object gate = new();
    private readonly Timer cleanup;
    public TunnelBroker() => cleanup = new(_ => Clean(), null, 10_000, 10_000);
    private void Clean()
    {
        foreach (var pair in tunnels)
            if (!pair.Value.Pumping && DateTimeOffset.UtcNow - pair.Value.Created > TimeSpan.FromSeconds(45)) Finish(pair.Key, pair.Value);
    }
    private void Finish(string id, Tunnel tunnel)
    {
        if (tunnels.TryRemove(id, out _))
        {
            tunnel.Manager?.Abort(); tunnel.Agent?.Abort(); tunnel.Done.TrySetResult();
        }
    }
    public TunnelTicket Create(string requester, string target)
    {
        if (target is null || target.Length != 68 || !target.StartsWith("rdm-", StringComparison.Ordinal) || !target[4..].All(Uri.IsHexDigit)) throw new ArgumentException("Invalid target.");
        lock(gate)
        {
            if (tunnels.Count >= 512 || tunnels.Values.Count(t => t.Ticket.Requester == requester || t.Ticket.Target == target) >= 24) throw new InvalidOperationException("Relay capacity reached.");
            var ticket = new TunnelTicket(Guid.NewGuid().ToString("N"), requester, target);
            tunnels[ticket.Id] = new(ticket); return ticket;
        }
    }
    public async Task<TunnelTicket?> Poll(string target, CancellationToken ct)
    {
        for (int attempt = 0; attempt < 20; attempt++)
        {
            foreach (var tunnel in tunnels.Values)
            {
                lock(tunnel)
                {
                    if (tunnel.Ticket.Target == target && !tunnel.Announced && DateTimeOffset.UtcNow - tunnel.Created < TimeSpan.FromSeconds(40))
                    { tunnel.Announced = true; return tunnel.Ticket; }
                }
            }
            await Task.Delay(500, ct);
        }
        return null;
    }
    public async Task Join(HttpContext context, string id, string role, string identity)
    {
        if (!tunnels.TryGetValue(id, out var tunnel)) { context.Response.StatusCode = 404; return; }
        lock(tunnel)
        {
            bool valid = role == "manager" ? identity == tunnel.Ticket.Requester && !tunnel.ManagerClaimed : role == "agent" && identity == tunnel.Ticket.Target && !tunnel.AgentClaimed;
            if (!valid) { context.Response.StatusCode = 403; return; }
            if (!context.WebSockets.IsWebSocketRequest) { context.Response.StatusCode = 400; return; }
            if (role == "manager") tunnel.ManagerClaimed = true; else tunnel.AgentClaimed = true;
        }
        try
        {
            using var socket = await context.WebSockets.AcceptWebSocketAsync();
            bool pump;
            lock(tunnel)
            {
                if (role == "manager") tunnel.Manager = socket; else tunnel.Agent = socket;
                pump = tunnel.Agent is not null && tunnel.Manager is not null && !tunnel.Pumping;
                if (pump) tunnel.Pumping = true;
            }
            if (pump) _ = PumpPair(id, tunnel);
            await tunnel.Done.Task.WaitAsync(context.RequestAborted);
        }
        finally { Finish(id,tunnel); }
    }
    private async Task PumpPair(string id, Tunnel tunnel)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromHours(6));
        async Task Pump(WebSocket source, WebSocket destination)
        {
            byte[] buffer = new byte[64 * 1024];
            while (!timeout.IsCancellationRequested)
            {
                var result = await source.ReceiveAsync(buffer.AsMemory(), timeout.Token);
                if (result.MessageType != WebSocketMessageType.Binary) break;
                await destination.SendAsync(buffer.AsMemory(0, result.Count), WebSocketMessageType.Binary, result.EndOfMessage, timeout.Token);
            }
        }
        try
        {
            var first = Pump(tunnel.Manager!, tunnel.Agent!); var second = Pump(tunnel.Agent!, tunnel.Manager!);
            await Task.WhenAny(first,second); timeout.Cancel();
            try { await Task.WhenAll(first,second); } catch (Exception e) when(e is OperationCanceledException or WebSocketException or IOException or ObjectDisposedException) { }
        }
        catch (Exception e) when (e is OperationCanceledException or WebSocketException or IOException or ObjectDisposedException) { }
        finally { Finish(id,tunnel); }
    }
    public void Dispose() { cleanup.Dispose(); foreach(var pair in tunnels) Finish(pair.Key,pair.Value); }
}
