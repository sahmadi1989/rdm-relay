namespace RDM.Contracts;
public sealed record TunnelRequest(string Target);
public sealed record TunnelTicket(string Id, string Requester, string Target);
public sealed record RemoteEntry(string Name, string Path, bool IsDirectory, long Size, DateTime LastWriteUtc);
public sealed record FileManifest(string Path, long Size, int ChunkSize, string Version, long LastWriteTicks, string[] Hashes);
public sealed class FileCommand
{
    public string Command { get; set; } = "";
    public string Path { get; set; } = "";
    public string Password { get; set; } = "";
    public string Version { get; set; } = "";
    public long LastWriteTicks { get; set; }
    public long Offset { get; set; }
    public int Length { get; set; }
}
public sealed class FileReply
{
    public string Error { get; set; } = "";
    public RemoteEntry[]? Entries { get; set; }
    public FileManifest? Manifest { get; set; }
    public int Length { get; set; }
    public string Hash { get; set; } = "";
}
