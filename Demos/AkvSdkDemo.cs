extern alias azcore;
using Azure.Security.KeyVault.Secrets;
using TokenBindingShowcase;
using MI = azcore::Azure.Identity;

namespace TokenBindingShowcase.Demos;

/// <summary>
/// Path (menu 7) - Azure Key Vault SDK. A ManagedIdentityCredential from the binding-enabled
/// Azure.Core 1.60.0-alpha (aliased 'azcore' to avoid the type clash with the transitive
/// Azure.Identity that Microsoft.Identity.Web pulls in) is passed to SecretClient; on a
/// supported (KeyGuard) host token binding (mTLS PoP) is ON by default and applied transparently.
/// </summary>
public static class AkvSdkDemo
{
    public static async Task RunAsync(AppSettings s)
    {
        Ux.Section("[7]  Azure Key Vault SDK  --  ManagedIdentityCredential");
        Ux.Context(
            "Token binding applied transparently: pass a ManagedIdentityCredential to SecretClient",
            "and the Key Vault SDK acquires a bound token and calls over mTLS automatically.",
            "No certificate handling or headers to manage yourself.");

        if (string.IsNullOrWhiteSpace(s.KeyVaultUrl) || string.IsNullOrWhiteSpace(s.SecretName))
        {
            Ux.Warn("Set TokenBinding:KeyVaultUrl and TokenBinding:SecretName in appsettings.json to run this demo.");
            return;
        }

        MI.ManagedIdentityId id = s.IsUserAssigned
            ? MI.ManagedIdentityId.FromUserAssignedClientId(s.UserAssignedClientId)
            : MI.ManagedIdentityId.SystemAssigned;

        var options = new MI.ManagedIdentityCredentialOptions(id);
        // Token binding is ON by default on a supported host. To opt out:
        //   options.DisableMtlsProofOfPossession = true;
        var credential = new MI.ManagedIdentityCredential(options);

        var client = new SecretClient(new Uri(s.KeyVaultUrl), credential);

        Ux.Info($"SecretClient.GetSecretAsync(\"{s.SecretName}\")");
        Ux.Info("    (ManagedIdentityCredential - binding applied transparently on a supported host)");

        try
        {
            var secret = await client.GetSecretAsync(s.SecretName);
            Ux.Ok($"Got secret '{secret.Value.Name}' (value length {secret.Value.Value?.Length ?? 0}).");
            Ux.Takeaway("The credential + client handled the bound mTLS call end-to-end -- zero plumbing.");
        }
        catch (Exception ex)
        {
            Ux.Error("AKV SDK call failed (expected off a KeyGuard-enabled VM / without RBAC)", ex);
        }
    }
}
