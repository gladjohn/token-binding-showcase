using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TokenBindingShowcase;

namespace TokenBindingShowcase.Demos;

/// <summary>
/// Path 3 - mint a self-signed certificate from BOTH keys into CurrentUser\My so you can open
/// certmgr.msc and compare: the KeyGuard-backed cert's private key is NON-exportable, while the
/// software-backed cert's private key IS exportable.
/// </summary>
public static class CertDemo
{
    public static Task RunAsync(AppSettings s)
    {
        Ux.Section("[3]  Create certificates from both keys (CurrentUser\\My)");
        Ux.Context(
            "Mints a self-signed certificate backed by each key and installs it in your personal store.",
            "Open  certmgr.msc -> Personal -> Certificates  to compare the two:",
            "the KeyGuard-backed cert's private key is NON-exportable; the software one IS exportable.");

        // KeyGuard-backed certificate (non-exportable private key)
        CngKey? kg = KeyOps.OpenOrCreateKeyGuard();
        if (kg is null)
        {
            Ux.Warn("KeyGuard key unavailable (VBS off) - skipping the non-exportable certificate.");
        }
        else
        {
            using (kg)
            {
                X509Certificate2 cert = KeyOps.CreateAndStoreCert(kg, "DemoKeyGuard-NonExportable", "DemoKeyGuard (non-exportable)");
                Ux.Ok($"Installed  CN=DemoKeyGuard-NonExportable   thumbprint {cert.Thumbprint}");
                ReportExportable(cert);
            }
        }

        // Software-backed certificate (exportable private key)
        using (CngKey sw = KeyOps.OpenOrCreateSoftware())
        {
            X509Certificate2 cert = KeyOps.CreateAndStoreCert(sw, "DemoSoftware-Exportable", "DemoSoftware (exportable)");
            Ux.Ok($"Installed  CN=DemoSoftware-Exportable     thumbprint {cert.Thumbprint}");
            ReportExportable(cert);
        }

        Ux.Info("Open  certmgr.msc  ->  Personal  ->  Certificates  to view both certificates.");
        Ux.Takeaway("Same cert flow, two keys: the KeyGuard private key can't be exported; the software one can.");
        return Task.CompletedTask;
    }

    private static void ReportExportable(X509Certificate2 cert)
    {
        using RSA? rsa = cert.GetRSAPrivateKey();
        bool exportable = false;
        try { _ = rsa?.ExportPkcs8PrivateKey(); exportable = rsa is not null; }
        catch (CryptographicException) { exportable = false; }

        if (exportable)
            Ux.Danger("   private key is EXPORTABLE");
        else
            Ux.Ok("   private key is NON-exportable");
    }
}
