using System.Collections.Concurrent;
using System.Security.Cryptography;
using RDM.Security;
namespace RDM.ConnectionServer;
public sealed class AuthState(TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private sealed record PendingChallenge(string Key, string Nonce, DateTimeOffset Expires);
    private readonly ConcurrentDictionary<string, PendingChallenge> challenges = new();
    private readonly ConcurrentDictionary<string, (string Id, DateTimeOffset Expires)> sessions = new();
    private readonly object gate = new();
    public RDM.Contracts.ChallengeReply Challenge(string publicKey)
    {
        using var key = DeviceIdentity.PublicKey(publicKey);
        var canonical = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        lock (gate) {
            Clean();
            if (challenges.Count >= 10_000) throw new InvalidOperationException("Authentication capacity reached.");
            var id = Guid.NewGuid().ToString("N"); var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            challenges[id] = new(canonical, nonce, clock.GetUtcNow().AddMinutes(1));
            return new(id, nonce, DeviceIdentity.Id(key.ExportSubjectPublicKeyInfo()));
        }
    }
    public (RDM.Contracts.SessionReply Reply, string Key)? Verify(string challengeId, string signature)
    {
        if (!challenges.TryRemove(challengeId, out var challenge) || challenge.Expires <= clock.GetUtcNow()) return null;
        try {
            using var key = DeviceIdentity.PublicKey(challenge.Key);
            if (!key.VerifyData(DeviceIdentity.ProofData(challengeId, challenge.Nonce), Convert.FromBase64String(signature), HashAlgorithmName.SHA256)) return null;
            var id = DeviceIdentity.Id(key.ExportSubjectPublicKeyInfo());
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)); var expires = clock.GetUtcNow().AddMinutes(15);
            lock (gate) { Clean(); if (sessions.Count >= 10_000) return null; sessions[Hash(token)] = (id, expires); }
            return (new(token, id, expires), challenge.Key);
        } catch (Exception e) when (e is FormatException or CryptographicException) { return null; }
    }
    private static string Hash(string token) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));
    public string? Authenticate(string token) => sessions.TryGetValue(Hash(token), out var session) && session.Expires > clock.GetUtcNow() ? session.Id : null;
    private void Clean()
    {
        var now = clock.GetUtcNow();
        foreach (var item in challenges) if (item.Value.Expires <= now) challenges.TryRemove(item.Key, out _);
        foreach (var item in sessions) if (item.Value.Expires <= now) sessions.TryRemove(item.Key, out _);
    }
}
