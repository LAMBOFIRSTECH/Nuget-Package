using System.Net.Sockets;
using System.Security.Cryptography;
using CustomVaultPackage.Middlewares;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods.AppRole;
using VaultSharp.V1.AuthMethods.Token;

namespace CustomVaultPackage.Services;


public class HashicorpVaultService(IConfiguration configuration)
{
    private readonly string hashiCorpHttpClient = configuration[
        "HashiCorp:HttpClient:VaultAddress"
    ]!;

    private async Task<string> EstablishConnectionWithVaultUsingAppRole()
    {
        var hashiCorpRoleID = configuration["HashiCorp:AppRole:RoleID"];
        var hashiCorpSecretID = configuration["HashiCorp:AppRole:SecretID"];
        if (
            string.IsNullOrEmpty(hashiCorpRoleID)
            || string.IsNullOrEmpty(hashiCorpSecretID)
            || string.IsNullOrEmpty(hashiCorpHttpClient)
        )
        {
            throw new InvalidOperationException(
                "💢 Empty or invalid HashiCorp Vault configurations."
            );
        }
        var appRoleAuthMethodInfo = new AppRoleAuthMethodInfo(hashiCorpRoleID, hashiCorpSecretID);
        var vaultClientSettings = new VaultClientSettings(
            $"{hashiCorpHttpClient}",
            appRoleAuthMethodInfo
        );
        var vaultClient = new VaultClient(vaultClientSettings);
        try
        {
            var authResponse = await vaultClient.V1.Auth.AppRole.LoginAsync(appRoleAuthMethodInfo);
            string token = authResponse.AuthInfo.ClientToken;
            if (string.IsNullOrEmpty(token))
                throw new InvalidOperationException("💢 Empty token retrieve from HashiCorp Vault");
            return token;
        }
        catch (Exception ex) when (ex.InnerException is SocketException)
        {
            throw new InvalidOperationException(
                "💢 The service is unavailable. Please retry soon.",
                ex
            );
        }
    }

    public async Task<RsaSecurityKey> GetJwtSigningKeyFromVaultServer()
    {
        string vautlAppRoleToken = await EstablishConnectionWithVaultUsingAppRole();
        var vaultClient = new VaultClient(
            new VaultClientSettings(
                $"{hashiCorpHttpClient}",
                new TokenAuthMethodInfo(vautlAppRoleToken)
            )
        );
        try
        {
            var secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(
                configuration["HashiCorp:JwtPublicKeyPath"]
            );
            if (secret == null)
            {
                throw new InvalidOperationException("Le secret Vault est introuvable.");
            }
            var secretData = secret.Data.Data;
            if (!secretData.TryGetValue("authenticationSignatureKey", out object? value))
            {
                throw new InvalidOperationException(
                    "La clé publique 'authenticationSignatureKey' est introuvable."
                );
            }
            string rawPublicKeyPem = value.ToString()!;
            rawPublicKeyPem = rawPublicKeyPem.Trim();
            if (
                !rawPublicKeyPem.Contains("-----BEGIN RSA PUBLIC KEY-----")
                || !rawPublicKeyPem.Contains("-----END RSA PUBLIC KEY-----")
            )
            {
                throw new Exception("La clé récupérée n'a pas le bon format PEM.");
            }
            string keyBody = rawPublicKeyPem
                .Replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .Replace("-----END RSA PUBLIC KEY-----", "")
                .Replace("\r", "")
                .Replace("\n", "")
                .Trim();
            if (string.IsNullOrEmpty(keyBody))
                throw new Exception("Le contenu de la clé est vide après le nettoyage.");
            string formattedPublicKeyPem =
                "-----BEGIN RSA PUBLIC KEY-----\n"
                + string.Join(
                    "\n",
                    Enumerable
                        .Range(0, (keyBody.Length + 63) / 64)
                        .Select(i =>
                            keyBody.Substring(i * 64, Math.Min(64, keyBody.Length - (i * 64)))
                        )
                )
                + "\n-----END RSA PUBLIC KEY-----";
            var rsa = RSA.Create();
            rsa.ImportFromPem(formattedPublicKeyPem);
            var rsaSecurityKey = new RsaSecurityKey(rsa);
            return rsaSecurityKey;
        }
        catch (FormatException ex)
        {
            throw new Exception("Erreur lors de la conversion de la clé publique Base64.", ex);
        }
        catch (Exception ex)
        {
            throw new Exception("Erreur lors de la récupération de la clé publique dans Vault", ex);
        }
    }

    public async Task<string> GetClientCertificatePassword()
    {
        string vautlAppRoleToken = await EstablishConnectionWithVaultUsingAppRole();
        var vaultClient = new VaultClient(
            new VaultClientSettings(
                $"{hashiCorpHttpClient}",
                new TokenAuthMethodInfo(vautlAppRoleToken)
            )
        );
        var secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(
            configuration["HashiCorp:CertPath"]
        );
        if (secret == null)
            throw new VaultConfigurationException(404, "Error", "Le secret Vault est introuvable.");
        var secretData = secret.Data.Data;
        if (!secretData.TryGetValue("certpass", out object? value))
            throw new VaultConfigurationException(
                404,
                "Error",
                "❌ Key 'password' not found for Client certificate."
            );
        return value.ToString()!;
    }

    public async Task<string> GetRabbitConnectionStringFromVault()
    {
        string vautlAppRoleToken = await EstablishConnectionWithVaultUsingAppRole();
        var vaultClient = new VaultClient(
            new VaultClientSettings(
                $"{hashiCorpHttpClient}",
                new TokenAuthMethodInfo(vautlAppRoleToken)
            )
        );
        var secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(
            configuration["HashiCorp:RabbitMqPath"]
        );
        if (secret == null)
            throw new VaultConfigurationException(404, "Error", "Le secret Vault est introuvable.");

        var secretData = secret.Data.Data;
        if (!secretData.TryGetValue("rabbitMqConnectionString", out object? value))
            throw new VaultConfigurationException(
                404,
                "Error",
                "❌ Key 'rabbitMqConnectionString' not found."
            );

        return value.ToString()!;
    }
}
