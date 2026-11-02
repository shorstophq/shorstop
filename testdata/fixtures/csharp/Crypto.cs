// Fixture: .NET crypto, plus near-misses.
using System.Security.Cryptography;

class Crypto {
    void Run() {
        var rsa = new RSACryptoServiceProvider(2048);
        using var rsa2 = RSA.Create();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var md5 = MD5.Create();
        var sha = new SHA1Managed();
        var tdes = TripleDES.Create();
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;

        // Near-misses:
        using var ok = SHA256.Create();
        var desc = "DESCRIPTION";
    }
}
