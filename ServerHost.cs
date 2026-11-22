using System.Threading.RateLimiting;
using RDM.Contracts;
using RDM.Storage;
using RDM.ConnectionServer;
namespace RDM.ConnectionServer;
public static class ServerHost {
public static WebApplication Create(string[] args, Action<WebApplicationBuilder>? configure = null) {
var builder = WebApplication.CreateBuilder(args);
configure?.Invoke(builder);
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 16 * 1024);
builder.Services.AddSingleton<AuthState>();
builder.Services.AddSingleton<TunnelBroker>();
builder.Services.AddSingleton(sp => new RdmStore(sp.GetRequiredService<IConfiguration>()["RDM_DATABASE"] ?? Path.Combine(AppContext.BaseDirectory, "data", "server.db")));
builder.Services.AddRateLimiter(o => {
    o.RejectionStatusCode = 429;
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions { PermitLimit = 120, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
var app = builder.Build();
app.Services.GetRequiredService<RdmStore>().Initialize();
var forwarding = ProxyConfiguration.Create(app.Configuration);
if(forwarding is not null)app.UseForwardedHeaders(forwarding);
app.Use(async (context, next) => {
    bool healthProbe=HttpMethods.IsGet(context.Request.Method)&&context.Request.Path=="/health";
    if (!healthProbe && !context.Request.IsHttps && !(app.Environment.IsDevelopment() && System.Net.IPAddress.IsLoopback(context.Connection.RemoteIpAddress ?? System.Net.IPAddress.None))) {
        context.Response.StatusCode = 400; return;
    }
    await next(context);
});
app.UseRateLimiter();
app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(20) });
app.MapGet("/health", () => Results.Ok(new { status = "ok", protocol = 1 }));
app.MapPost("/v1/auth/challenge", (ChallengeRequest request, AuthState auth) => {
    if (string.IsNullOrWhiteSpace(request.PublicKey) || request.PublicKey.Length > 512) return Results.BadRequest();
    try { return Results.Ok(auth.Challenge(request.PublicKey)); }
    catch (Exception e) when (e is FormatException or System.Security.Cryptography.CryptographicException or ArgumentException) { return Results.BadRequest(); }
    catch (InvalidOperationException) { return Results.StatusCode(503); }
});
app.MapPost("/v1/auth/prove", (Proof request, AuthState auth, RdmStore store) => {
    if (string.IsNullOrWhiteSpace(request.ChallengeId) || string.IsNullOrWhiteSpace(request.Signature) || request.Signature.Length > 256) return Results.BadRequest();
    var result = auth.Verify(request.ChallengeId, request.Signature);
    if (result is null) return Results.Unauthorized();
    store.Register(result.Value.Reply.DeviceId, result.Value.Key); return Results.Ok(result.Value.Reply);
});
app.Use(async (context, next) => {
    if (context.Request.Path.StartsWithSegments("/v1/devices") || context.Request.Path.StartsWithSegments("/v1/trust") || context.Request.Path.StartsWithSegments("/v1/tunnels")) {
        var header = context.Request.Headers.Authorization.ToString();
        var id = header.StartsWith("Bearer ", StringComparison.Ordinal) ? context.RequestServices.GetRequiredService<AuthState>().Authenticate(header[7..]) : null;
        if (id is null) { context.Response.StatusCode = 401; return; }
        context.Items["device"] = id;
    }
    await next(context);
});
// Trust approval must originate from the owner identity, through its future local administration UI.
app.MapPost("/v1/trust", (HttpContext ctx, TrustRequest request, RdmStore store) => {
    if (string.IsNullOrWhiteSpace(request.PeerDeviceId) || request.PeerDeviceId.Length != 68 || !request.PeerDeviceId.StartsWith("rdm-", StringComparison.Ordinal)) return Results.BadRequest();
    try { store.SetTrust((string)ctx.Items["device"]!, request.PeerDeviceId, true); return Results.NoContent(); }
    catch (Microsoft.Data.Sqlite.SqliteException e) when (e.SqliteErrorCode == 19) { return Results.BadRequest(); }
});
app.MapDelete("/v1/trust/{peer}", (HttpContext ctx, string peer, RdmStore store) => { store.SetTrust((string)ctx.Items["device"]!, peer, false); return Results.NoContent(); });
app.MapGet("/v1/devices/{target}/authorization", (HttpContext ctx, string target, RdmStore store) =>
    store.IsTrusted(target, (string)ctx.Items["device"]!) ? Results.Ok(new { authorized = true }) : Results.StatusCode(403));
app.MapPost("/v1/tunnels", (HttpContext ctx, TunnelRequest request, TunnelBroker broker) => {
    try { return Results.Ok(broker.Create((string)ctx.Items["device"]!, request.Target)); }
    catch(ArgumentException) { return Results.BadRequest(); }
    catch(InvalidOperationException) { return Results.StatusCode(429); }
});
app.MapGet("/v1/tunnels/pending", async (HttpContext ctx, TunnelBroker broker) => {
    var ticket = await broker.Poll((string)ctx.Items["device"]!, ctx.RequestAborted);
    return ticket is null ? Results.NoContent() : Results.Ok(ticket);
});
app.MapGet("/v1/tunnels/{id}/{role}", async (HttpContext ctx, string id, string role, TunnelBroker broker) =>
    await broker.Join(ctx,id,role,(string)ctx.Items["device"]!));
return app;

}}
