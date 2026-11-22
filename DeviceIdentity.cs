using System.Security.Cryptography;
using System.Text;
namespace RDM.Security;
public static class DeviceIdentity
{
    public static ECDsa Create() => ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public static string Id(ReadOnlySpan<byte> publicKey) => "rdm-" + Convert.ToHexStringLower(SHA256.HashData(publicKey));
    public static ECDsa PublicKey(string encoded)
    {
        var bytes = Convert.FromBase64String(encoded);
        var key = ECDsa.Create();
        try {
            key.ImportSubjectPublicKeyInfo(bytes, out int read);
            if (read != bytes.Length || key.KeySize != 256 || key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
                throw new CryptographicException("Only P-256 is supported.");
            return key;
        } catch { key.Dispose(); throw; }
    }
    public static byte[] ProofData(string challengeId, string nonce) => Encoding.UTF8.GetBytes($"RDM/auth/v1\n{challengeId}\n{nonce}");
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static ECDsa LoadOrCreate(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        if (!File.Exists(path)) {
            using var generated = Create();
            byte[] raw = generated.ExportPkcs8PrivateKey();
            try {
                byte[] protectedKey = ProtectedData.Protect(raw, null, DataProtectionScope.CurrentUser);
                string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try {
                        var acl = new System.Security.AccessControl.FileSecurity();
                        acl.SetAccessRuleProtection(true, false);
                        acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                            System.Security.Principal.WindowsIdentity.GetCurrent().User!,
                            System.Security.AccessControl.FileSystemRights.FullControl,
                            System.Security.AccessControl.AccessControlType.Allow));
                    using (var file = new FileInfo(temporary).Create(FileMode.CreateNew,
                        System.Security.AccessControl.FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, acl)) {
                        file.Write(protectedKey); file.Flush(true);
                    }
                    try { File.Move(temporary, path, false); }
                    catch (IOException) when (File.Exists(path)) { /* Another initializer won. */ }
                } finally { if (File.Exists(temporary)) File.Delete(temporary); }
            } finally { CryptographicOperations.ZeroMemory(raw); }
        }
        byte[] decoded = ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser);
        var key = Create();
        try { key.ImportPkcs8PrivateKey(decoded, out _); return key; }
        catch { key.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(decoded); }
    }
    public static byte[] Backup(ECDsa key, string password)
    {
        if (password.Length < 16) throw new ArgumentException("Use a passphrase of at least 16 characters.");
        return key.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000));
    }
    public static ECDsa Restore(byte[] backup, string password)
    {
        var key = Create();
        try { key.ImportEncryptedPkcs8PrivateKey(password, backup, out int read); if (read != backup.Length) throw new CryptographicException(); return key; }
        catch { key.Dispose(); throw; }
    }
}
