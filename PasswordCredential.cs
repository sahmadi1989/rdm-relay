using System.Security.Cryptography;
namespace RDM.Security;

// Agent-local verifier. Never send this record to the rendezvous server.
public sealed class PasswordCredential
{
    private const int Iterations = 600_000;
    private readonly byte[] salt;
    private readonly byte[] hash;
    private PasswordCredential(byte[] salt, byte[] hash) { this.salt = salt; this.hash = hash; }
    public static PasswordCredential Create(string password)
    {
        if (password.Length < 12 || password.Length > 1024) throw new ArgumentException("Password must contain 12 to 1024 characters.");
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        return new(salt, Derive(password, salt));
    }
    public bool Verify(string password)
    {
        if (password.Length > 1024) return false;
        byte[] candidate = Derive(password, salt);
        try { return CryptographicOperations.FixedTimeEquals(candidate, hash); }
        finally { CryptographicOperations.ZeroMemory(candidate); }
    }
    private static byte[] Derive(string password, byte[] salt) => Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
    public byte[] ExportVerifier()
    {
        // Versioned fixed-size encoding prevents attacker-controlled KDF work factors.
        byte[] data = new byte[65]; data[0] = 1; salt.CopyTo(data, 1); hash.CopyTo(data, 33); return data;
    }
    public static PasswordCredential ImportVerifier(byte[] data)
    {
        if (data.Length != 65 || data[0] != 1) throw new CryptographicException("Invalid password verifier.");
        return new(data[1..33], data[33..65]);
    }
}
