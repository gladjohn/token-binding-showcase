using System.Security.Cryptography;
using TokenBindingShowcase;

namespace TokenBindingShowcase.Demos;

/// <summary>
/// Path 2 - Non-KeyGuard (software) key. The contrast to option 1: an ordinary RSA key that is
/// marked exportable, so its private key can be pulled out in the clear. This is what KeyGuard
/// prevents.
/// </summary>
public static class SoftwareKeyDemo
{
    public static Task RunAsync(AppSettings s)
    {
        Ux.Section("[2]  Non-KeyGuard (software) key demo  --  create, list, export");
        Ux.Context(
            "The CONTRAST to option 1: an ordinary software RSA key, NOT protected by VBS/KeyGuard.",
            "It is marked exportable, so its private key can be pulled out of the machine in the clear.",
            $"Key name: '{KeyOps.SoftwareKeyName}'.");

        Ux.Info("2A  Create a software RSA-2048 key  (ExportPolicy=AllowExport, no VBS)");
        CngKey key;
        try
        {
            key = KeyOps.CreateSoftwareKey();
            Ux.Ok($"Software key '{KeyOps.SoftwareKeyName}' created.");
        }
        catch (Exception ex)
        {
            Ux.Error("Software key creation failed", ex);
            return Task.CompletedTask;
        }

        using (key)
        {
            using var rsa = new RSACng(key);
            Ux.Info("2B  List the key:");
            Ux.Info($"    algorithm / size   : {key.Algorithm.Algorithm} / {rsa.KeySize} bits");
            Ux.Info($"    export policy      : {key.ExportPolicy}");
            Ux.Info($"    KeyGuard-protected : {KeyOps.IsKeyGuardProtected(key)}");

            Ux.Info("2C  Export the PRIVATE key");
            if (KeyOps.TryExportPrivateKey(key, out string detail))
            {
                Ux.Danger($"Key is EXPORTABLE - the private key was pulled out ({detail}).");
                Ux.Takeaway("A software key can be exported and stolen. KeyGuard (option 1) prevents exactly this.");
            }
            else
            {
                Ux.Ok($"Export blocked unexpectedly ({detail}).");
            }
        }
        return Task.CompletedTask;
    }
}
