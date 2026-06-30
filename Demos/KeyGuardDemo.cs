using System.Security.Cryptography;
using TokenBindingShowcase;

namespace TokenBindingShowcase.Demos;

/// <summary>
/// Path 1 - KeyGuard key demo. Creates a VBS-isolated (KeyGuard) CNG RSA key, lists it,
/// and proves the private key cannot be exported. This is the hardware-protected key that a
/// bound (mtls_pop) token is later tied to. Requires a Trusted Launch / Confidential VM with
/// VBS + KeyGuard. Uses a distinct key name so it never collides with MSAL's own key.
/// (Key-creation flags mirror MSAL's WindowsCngKeyOperations.)
/// </summary>
public static class KeyGuardDemo
{
    private const string ProviderName = "Microsoft Software Key Storage Provider";
    private const string KeyName = "DemoKeyGuardKey";   // distinct from MSAL's 'KeyGuardRSAKey'
    private const string VirtualIsoProperty = "Virtual Iso";
    private const int KeySize = 2048;

    // KeyGuard + per-boot creation flags (NCRYPT_USE_VIRTUAL_ISOLATION_FLAG / NCRYPT_USE_PER_BOOT_KEY_FLAG).
    private const CngKeyCreationOptions NCryptUseVirtualIsolationFlag = (CngKeyCreationOptions)0x00020000;
    private const CngKeyCreationOptions NCryptUsePerBootKeyFlag = (CngKeyCreationOptions)0x00040000;
    private const int NTE_NOT_SUPPORTED = unchecked((int)0x80890014);

    public static Task RunAsync(AppSettings s)
    {
        Ux.Section("[1]  KeyGuard key demo  --  create, list, and (try to) export");
        Ux.Context(
            "KeyGuard keys live inside a VBS (Virtualization-Based Security) enclave on the VM.",
            "MSAL mints one of these and binds your token to it - so a stolen token is useless",
            "without the key, and the key can never leave the machine.",
            $"This demo uses a separate key name ('{KeyName}') so it won't collide with MSAL's.");

        CngKey? key = CreateKeyGuardKey();          // 1A
        if (key is null)
            return Task.CompletedTask;

        try
        {
            ListKey(key);                           // 1B
            TryExportPrivateKey(key);               // 1C
        }
        finally
        {
            key.Dispose();
        }

        return Task.CompletedTask;
    }

    // ---- 1A: create -------------------------------------------------------------------------
    private static CngKey? CreateKeyGuardKey()
    {
        Ux.Info("1A  Create a VBS-isolated KeyGuard RSA-2048 key");
        Ux.Info($"    Provider='{ProviderName}', KeyName='{KeyName}', flags=VirtualIsolation|PerBoot, ExportPolicy=None");

        var p = new CngKeyCreationParameters
        {
            Provider = new CngProvider(ProviderName),
            KeyUsage = CngKeyUsages.AllUsages,
            ExportPolicy = CngExportPolicies.None,   // non-exportable
            KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey
                               | NCryptUseVirtualIsolationFlag
                               | NCryptUsePerBootKeyFlag,
        };
        p.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(KeySize), CngPropertyOptions.None));

        try
        {
            CngKey key = CngKey.Create(CngAlgorithm.Rsa, KeyName, p);
            Ux.Ok($"KeyGuard key '{KeyName}' created.");
            return key;
        }
        catch (CryptographicException ex) when (ex.HResult == NTE_NOT_SUPPORTED || ex.Message.Contains("isolation"))
        {
            Ux.Warn("VBS key isolation is not available here - run on a Trusted Launch / Confidential VM with KeyGuard.");
            Ux.Info($"    ({ex.GetType().Name}: HR=0x{ex.HResult:X8})");
            return null;
        }
        catch (Exception ex)
        {
            Ux.Error("KeyGuard key creation failed", ex);
            return null;
        }
    }

    // ---- 1B: list ---------------------------------------------------------------------------
    private static void ListKey(CngKey key)
    {
        bool exists = CngKey.Exists(KeyName, new CngProvider(ProviderName),
                                    CngKeyOpenOptions.UserKey | CngKeyOpenOptions.Silent);
        bool guarded = IsKeyGuardProtected(key);
        using var rsa = new RSACng(key);

        Ux.Info("1B  List the key:");
        Ux.Info($"    exists in store    : {exists}");
        Ux.Info($"    algorithm / size   : {key.Algorithm.Algorithm} / {rsa.KeySize} bits");
        Ux.Info($"    export policy      : {key.ExportPolicy}");
        Ux.Info($"    KeyGuard-protected : {guarded}   (Virtual Iso property {(guarded ? "set" : "absent")})");
        Ux.Ok("Key is present and VBS-isolated.");
    }

    // ---- 1C: try export (must fail) ---------------------------------------------------------
    private static void TryExportPrivateKey(CngKey key)
    {
        Ux.Info("1C  Try to export the PRIVATE key (this should FAIL)");
        try
        {
            using var rsa = new RSACng(key);
            byte[] blob = rsa.ExportPkcs8PrivateKey();   // non-exportable -> throws
            Ux.Warn($"UNEXPECTED: private key exported ({blob.Length} bytes). The key is NOT protected!");
        }
        catch (CryptographicException ex)
        {
            Ux.Ok("Export BLOCKED - the private key never leaves the VBS enclave.");
            Ux.Info($"    ({ex.GetType().Name}: {ex.Message})");
            Ux.Takeaway("The KeyGuard key is non-exportable: a token bound to it can't be replayed without this VM.");
        }
    }

    private static bool IsKeyGuardProtected(CngKey key)
    {
        if (!key.HasProperty(VirtualIsoProperty, CngPropertyOptions.None))
            return false;
        byte[]? val = key.GetProperty(VirtualIsoProperty, CngPropertyOptions.None).GetValue();
        return val is { Length: > 0 } && val[0] != 0;
    }
}
