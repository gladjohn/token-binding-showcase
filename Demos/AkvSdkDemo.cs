using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using TokenBindingShowcase;

namespace TokenBindingShowcase.Demos;

/// <summary>
/// Path 3 - Azure Key Vault SDK. A ManagedIdentityCredential is passed to a SecretClient;
/// on a supported host token binding is applied transparently and the AKV call goes over mTLS.
///
/// NOTE: token binding (mTLS PoP) for the AKV SDK is a PREVIEW feature. The opt-out
/// (DisableMtlsProofOfPossession) and the bound behavior require the preview package feed
/// (Azure.Core 1.60.0-alpha...). With the public packages referenced here the call still
/// works, but the credential acquires a bearer token rather than a bound one.
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

        ManagedIdentityId id = s.IsUserAssigned
            ? ManagedIdentityId.FromUserAssignedClientId(s.UserAssignedClientId)
            : ManagedIdentityId.SystemAssigned;

        var options = new ManagedIdentityCredentialOptions(id);
        // Token binding is ON by default on a supported host. To opt out (preview feed only):
        //   options.DisableMtlsProofOfPossession = true;
        var credential = new ManagedIdentityCredential(options);

        var client = new SecretClient(new Uri(s.KeyVaultUrl), credential);

        Ux.Info($"SecretClient.GetSecretAsync(\"{s.SecretName}\")");
        Ux.Info("    (ManagedIdentityCredential - binding applied transparently on a supported host)");

        try
        {
            Response<KeyVaultSecret> secret = await client.GetSecretAsync(s.SecretName);
            Ux.Ok($"Got secret '{secret.Value.Name}' (value length {secret.Value.Value?.Length ?? 0}).");
            Ux.Takeaway("The credential + client handled the bound mTLS call end-to-end -- zero plumbing.");
        }
        catch (Exception ex)
        {
            Ux.Error("AKV SDK call failed (expected off a KeyGuard-enabled VM / without RBAC)", ex);
        }
    }
}
