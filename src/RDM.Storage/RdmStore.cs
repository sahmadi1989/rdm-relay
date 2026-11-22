using Microsoft.Data.Sqlite;
namespace RDM.Storage;
public sealed class RdmStore(string path)
{
    public sealed record RegisteredDevice(string Id, string LastAuthentication);
    public IReadOnlyList<RegisteredDevice> GetRegisteredDevices()
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT Id,LastSeen FROM Devices ORDER BY LastSeen DESC LIMIT 1000";
        using var reader = cmd.ExecuteReader();
        var result = new List<RegisteredDevice>();
        while (reader.Read()) result.Add(new(reader.GetString(0), DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(1)).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")));
        return result;
    }
    private SqliteConnection Open()
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, ForeignKeys = true, DefaultTimeout = 10 }.ToString());
        db.Open();
        using var command = db.CreateCommand(); command.CommandText = "PRAGMA synchronous=FULL;"; command.ExecuteNonQuery();
        return db;
    }
    public void Initialize()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var db = Open(); using var command = db.CreateCommand();
        command.CommandText = """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS SchemaVersion(Version INTEGER PRIMARY KEY);
        INSERT OR IGNORE INTO SchemaVersion VALUES(1);
        CREATE TABLE IF NOT EXISTS Devices(Id TEXT PRIMARY KEY, PublicKey TEXT NOT NULL, LastSeen INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS Trust(Owner TEXT NOT NULL REFERENCES Devices(Id), Peer TEXT NOT NULL REFERENCES Devices(Id), ApprovedAt INTEGER NOT NULL, PRIMARY KEY(Owner,Peer));
        CREATE TABLE IF NOT EXISTS Downloads(
          Id TEXT PRIMARY KEY, DeviceId TEXT NOT NULL, FileId TEXT NOT NULL, FileVersion TEXT NOT NULL,
          RemotePath TEXT NOT NULL, Destination TEXT NOT NULL UNIQUE, TempPath TEXT NOT NULL UNIQUE,
          FileSize INTEGER NOT NULL CHECK(FileSize>=0), ChunkSize INTEGER NOT NULL CHECK(ChunkSize>0),
          ChunkCount INTEGER NOT NULL CHECK(ChunkCount>=0), CompletionBitmap BLOB NOT NULL,
          Status TEXT NOT NULL, RetryCount INTEGER NOT NULL DEFAULT 0, LastActivity INTEGER NOT NULL,
          SettingsJson TEXT NOT NULL, FullHash BLOB, Priority INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS Chunks(
          DownloadId TEXT NOT NULL REFERENCES Downloads(Id) ON DELETE CASCADE,
          ChunkIndex INTEGER NOT NULL CHECK(ChunkIndex>=0), Offset INTEGER NOT NULL CHECK(Offset>=0),
          Length INTEGER NOT NULL CHECK(Length>0), Sha256 BLOB NOT NULL CHECK(length(Sha256)=32),
          PRIMARY KEY(DownloadId,ChunkIndex));
        """;
        command.ExecuteNonQuery();
    }
    public void Register(string id, string publicKey)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "INSERT INTO Devices VALUES($id,$key,$now) ON CONFLICT(Id) DO UPDATE SET LastSeen=$now WHERE PublicKey=$key";
        cmd.Parameters.AddWithValue("$id", id); cmd.Parameters.AddWithValue("$key", publicKey); cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeSeconds()); cmd.ExecuteNonQuery();
    }
    public void SetTrust(string owner, string peer, bool approved)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = approved ? "INSERT OR REPLACE INTO Trust VALUES($owner,$peer,unixepoch())" : "DELETE FROM Trust WHERE Owner=$owner AND Peer=$peer";
        cmd.Parameters.AddWithValue("$owner", owner); cmd.Parameters.AddWithValue("$peer", peer); cmd.ExecuteNonQuery();
    }
    public bool IsTrusted(string owner, string peer)
    {
        using var db = Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM Trust WHERE Owner=$owner AND Peer=$peer";
        cmd.Parameters.AddWithValue("$owner", owner); cmd.Parameters.AddWithValue("$peer", peer); return (long)cmd.ExecuteScalar()! == 1;
    }
}
