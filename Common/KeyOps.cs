using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TokenBindingShowcase;

/// <summary>
/// Shared Windows CNG key operations for the key/cert demos:
/// a VBS-isolated KeyGuard key (non-exportable) and an ordinary software key (exportable),
/// plus helpers to inspect, export, and mint self-signed certificates from them.
/// </summary>
public static class KeyOps
{
    public const string ProviderName = "Microsoft Software Key Storage Provider";
    public const string KeyGuardKeyName = "DemoKeyGuardKey";   // distinct from MSAL's 'KeyGuardRSAKey'
    public const string SoftwareKeyName = "DemoSoftwareKey";
    private const string VirtualIsoProperty = "Virtual Iso";
    private const int KeySize = 2048;

    // NCRYPT_USE_VIRTUAL_ISOLATION_FLAG / NCRYPT_USE_PER_BOOT_KEY_FLAG (KeyGuard).
    private const CngKeyCreationOptions NCryptUseVirtualIsolationFlag = (CngKeyCreationOptions)0x00020000;
    private const CngKeyCreationOptions NCryptUsePerBootKeyFlag = (CngKeyCreationOptions)0x00040000;
    private const int NTE_NOT_SUPPORTED = unchecked((int)0x80890014);

    public static bool IsVbsUnavailable(CryptographicException ex) =>
        ex.HResult == NTE_NOT_SUPPORTED ||
        ex.Message.Contains("isolation", StringComparison.OrdinalIgnoreCase);

    /// <summary>Creates a VBS-isolated, non-exportable KeyGuard RSA key. Throws if VBS is unavailable.</summary>
    public static CngKey CreateKeyGuardKey()
    {
        var p = new CngKeyCreationParameters
        {
            Provider = new CngProvider(ProviderName),
            KeyUsage = CngKeyUsages.AllUsages,
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey
                               | NCryptUseVirtualIsolationFlag
                               | NCryptUsePerBootKeyFlag,
        };
        p.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(KeySize), CngPropertyOptions.None));
        return CngKey.Create(CngAlgorithm.Rsa, KeyGuardKeyName, p);
    }

    /// <summary>Creates an ordinary software RSA key marked exportable (NOT KeyGuard-protected).</summary>
    public static CngKey CreateSoftwareKey()
    {
        var p = new CngKeyCreationParameters
        {
            Provider = new CngProvider(ProviderName),
            KeyUsage = CngKeyUsages.AllUsages,
            ExportPolicy = CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport,
            KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
        };
        p.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(KeySize), CngPropertyOptions.None));
        return CngKey.Create(CngAlgorithm.Rsa, SoftwareKeyName, p);
    }

    public static CngKey? OpenOrCreateKeyGuard()
    {
        var prov = new CngProvider(ProviderName);
        if (CngKey.Exists(KeyGuardKeyName, prov, CngKeyOpenOptions.UserKey))
            return CngKey.Open(KeyGuardKeyName, prov, CngKeyOpenOptions.UserKey | CngKeyOpenOptions.Silent);
        try { return CreateKeyGuardKey(); }
        catch (CryptographicException ex) when (IsVbsUnavailable(ex)) { return null; }
    }

    public static CngKey OpenOrCreateSoftware()
    {
        var prov = new CngProvider(ProviderName);
        return CngKey.Exists(SoftwareKeyName, prov, CngKeyOpenOptions.UserKey)
            ? CngKey.Open(SoftwareKeyName, prov, CngKeyOpenOptions.UserKey | CngKeyOpenOptions.Silent)
            : CreateSoftwareKey();
    }

    public static bool IsKeyGuardProtected(CngKey key)
    {
        if (!key.HasProperty(VirtualIsoProperty, CngPropertyOptions.None))
            return false;
        byte[]? v = key.GetProperty(VirtualIsoProperty, CngPropertyOptions.None).GetValue();
        return v is { Length: > 0 } && v[0] != 0;
    }

    /// <summary>Tries to export the private key. Returns true (with detail) if it is exportable.</summary>
    public static bool TryExportPrivateKey(CngKey key, out string detail)
    {
        try
        {
            using var rsa = new RSACng(key);
            byte[] blob = rsa.ExportPkcs8PrivateKey();
            detail = $"{blob.Length} bytes of PKCS#8 private key";
            return true;
        }
        catch (CryptographicException ex)
        {
            detail = ex.Message;
            return false;
        }
    }

    /// <summary>Mints a self-signed cert from an existing CNG key and installs it in CurrentUser\My.</summary>
    public static X509Certificate2 CreateAndStoreCert(CngKey key, string subjectCn, string friendlyName)
    {
        using var rsa = new RSACng(key);
        var req = new CertificateRequest($"CN={subjectCn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        try { cert.FriendlyName = friendlyName; } catch { /* best effort */ }

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
        return cert;
    }
}
