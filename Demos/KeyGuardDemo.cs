using System.Security.Cryptography;
using TokenBindingShowcase;

namespace TokenBindingShowcase.Demos;

/// <summary>
/// Path 1 - KeyGuard key. Creates a VBS-isolated key, lists it, and proves the private key
/// cannot be exported. This is the hardware-protected key a bound (mtls_pop) token ties to.
/// </summary>
public static class KeyGuardDemo
{
    public static Task RunAsync(AppSettings s)
    {
        Ux.Section("[1]  KeyGuard key demo  --  create, list, and (try to) export");
        Ux.Context(
            "KeyGuard keys live inside a VBS (Virtualization-Based Security) enclave on the VM.",
            "MSAL mints one of these and binds your token to it - so a stolen token is useless",
            "without the key, and the key can never leave the machine.",
            $"Uses a separate key name ('{KeyOps.KeyGuardKeyName}') so it won't collide with MSAL's.");

        Ux.Info($"1A  Create a VBS-isolated KeyGuard RSA-2048 key  (Provider='{KeyOps.ProviderName}', ExportPolicy=None)");
        CngKey key;
        try
        {
            key = KeyOps.CreateKeyGuardKey();
            Ux.Ok($"KeyGuard key '{KeyOps.KeyGuardKeyName}' created.");
        }
        catch (CryptographicException ex) when (KeyOps.IsVbsUnavailable(ex))
        {
            Ux.Warn("VBS key isolation is not available here - run on a Trusted Launch / Confidential VM with KeyGuard.");
            Ux.Info($"    ({ex.GetType().Name}: HR=0x{ex.HResult:X8})");
            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            Ux.Error("KeyGuard key creation failed", ex);
            return Task.CompletedTask;
        }

        using (key)
        {
            using var rsa = new RSACng(key);
            Ux.Info("1B  List the key:");
            Ux.Info($"    algorithm / size   : {key.Algorithm.Algorithm} / {rsa.KeySize} bits");
            Ux.Info($"    export policy      : {key.ExportPolicy}");
            Ux.Info($"    KeyGuard-protected : {KeyOps.IsKeyGuardProtected(key)}   (Virtual Iso property set)");

            Ux.Info("1C  Try to export the PRIVATE key (this should FAIL)");
            if (KeyOps.TryExportPrivateKey(key, out string detail))
            {
                Ux.Danger($"UNEXPECTED: private key exported - the key is NOT protected!  ({detail})");
            }
            else
            {
                Ux.Ok("Export BLOCKED - the private key never leaves the VBS enclave.");
                Ux.Info($"    ({detail})");
                Ux.Takeaway("The KeyGuard key is non-exportable: a token bound to it can't be replayed without this VM.");
            }
        }
        return Task.CompletedTask;
    }
}
