namespace RDM.Contracts;
public sealed record ChallengeRequest(string PublicKey);
public sealed record ChallengeReply(string ChallengeId, string Nonce, string DeviceId);
public sealed record Proof(string ChallengeId, string Signature);
public sealed record SessionReply(string Token, string DeviceId, DateTimeOffset Expires);
public sealed record TrustRequest(string PeerDeviceId);
