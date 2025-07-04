namespace AuthenticationServer.Controllers;

using Microsoft.IdentityModel.Tokens; // Necesario para RsaSecurityKey
using System.Security.Cryptography;
using System.Text;

public static class KeyGenerator {
    // Las claves pública y privada deben ser accesibles globalmente o inyectadas vía DI.
    public static RSA RsaPrivateKey { get; private set; }
    public static RSA RsaPublicKey { get; private set; }

    public static void GenerateRsaKeys(int keySize = 2048) {
        using(var rsa = RSA.Create(keySize)) {
            // Exportar la clave pública
            RsaPublicKey = RSA.Create();
            RsaPublicKey.ImportParameters(rsa.ExportParameters(false)); // false para clave pública

            // Exportar la clave privada
            RsaPrivateKey = RSA.Create();
            RsaPrivateKey.ImportParameters(rsa.ExportParameters(true)); // true para clave privada
        }
    }
    public static void LoadRsaKeys(int keySize = 2048) {
        using(var rsa = RSA.Create(keySize)) {
            // Exportar la clave pública
            RsaPublicKey = RSA.Create();
            RsaPublicKey.ImportParameters(rsa.ExportParameters(false)); // false para clave pública

            // Exportar la clave privada
            RsaPrivateKey = RSA.Create();
            RsaPrivateKey.ImportParameters(rsa.ExportParameters(true)); // true para clave privada
        }
    }

    public static string ExportPublicKeyToPEM() {
        var publicKeyBytes = RsaPublicKey.ExportSubjectPublicKeyInfo();
        var base64 = Convert.ToBase64String(publicKeyBytes);
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN PUBLIC KEY-----");
        for(int i = 0; i < base64.Length; i += 64) {
            builder.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
        }
        builder.AppendLine("-----END PUBLIC KEY-----");
        return builder.ToString();
    }

    // En un escenario real, se cargarían estas claves desde un certificado X.509
    // Por ejemplo:
    // public static RsaSecurityKey GetSigningSecurityKeyFromCertificate(string certificatePath, string password)
    // {
    //     var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificatePath, password);
    //     return new RsaSecurityKey(certificate.GetRSAPrivateKey());
    // }
    //
    // public static RsaSecurityKey GetValidationSecurityKeyFromCertificate(string certificatePath)
    // {
    //     var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificatePath);
    //     return new RsaSecurityKey(certificate.GetRSAPublicKey());
    // }
}
