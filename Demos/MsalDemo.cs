using System.Net.Http.Headers;
using System.Security.Authentication;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AppConfig;
using Microsoft.Identity.Client.KeyAttestation;
using TokenBindingShowcase;

namespace TokenBindingShowcase.Demos;

/// <summary>
/// Path 1 - MSAL .NET. Acquires a bound (mTLS PoP) Managed Identity token and,
/// optionally, calls Key Vault directly over mutual TLS with the binding certificate.
/// </summary>
public static class MsalDemo
{
    public static async Task RunAsync(AppSettings s)
    {
        Ux.Section("[3]  MSAL .NET  --  BOUND token (mTLS Proof-of-Possession)");
        Ux.Context(
            "MSAL acquires a token cryptographically BOUND to a key it controls.",
            "Flow: IMDSv2 getPlatformMetadata -> KeyGuard key + CSR -> MAA attestation",
            "      -> /issuecredential (binding cert) -> ESTS over mTLS -> mtls_pop token.",
            "The call below presents the cert on the TLS channel + the Key Vault opt-in header.");

        ManagedIdentityId id = s.IsUserAssigned
            ? ManagedIdentityId.WithUserAssignedClientId(s.UserAssignedClientId)
            : ManagedIdentityId.SystemAssigned;

        IManagedIdentityApplication mi = ManagedIdentityApplicationBuilder
            .Create(id)
            .Build();

        Ux.Info($"AcquireTokenForManagedIdentity(\"{s.Resource}\")");
        Ux.Info("    .WithMtlsProofOfPossession().WithAttestationSupport()");

        try
        {
            AuthenticationResult result = await mi
                .AcquireTokenForManagedIdentity(s.Resource)
                .WithMtlsProofOfPossession()
                .WithAttestationSupport()
                .ExecuteAsync();

            Ux.PrintToken(result.TokenType, result.AccessToken, result.ExpiresOn, result.BindingCertificate);

            if (s.CallKeyVault
                && result.BindingCertificate is not null
                && !string.IsNullOrWhiteSpace(s.KeyVaultUrl)
                && !string.IsNullOrWhiteSpace(s.SecretName))
            {
                await CallKeyVaultOverMtlsAsync(result, s);
            }

            Ux.Takeaway("token_type = mtls_pop with a binding certificate. Replayed without that cert from another VM, this token is rejected (401).");
        }
        catch (Exception ex)
        {
            Ux.Error("MSAL token acquisition failed (expected off a KeyGuard-enabled VM)", ex);
        }
    }

    /// <summary>
    /// Pins the binding certificate to the TLS channel, sends the token with the
    /// mtls_pop scheme, and includes the Key Vault opt-in header.
    /// </summary>
    private static async Task CallKeyVaultOverMtlsAsync(AuthenticationResult result, AppSettings s)
    {
        Ux.Info("Calling Key Vault over mTLS with the binding certificate...");

        using var handler = new HttpClientHandler
        {
            ClientCertificateOptions = ClientCertificateOption.Manual,
            SslProtocols = SslProtocols.Tls12,
        };
        handler.ClientCertificates.Add(result.BindingCertificate!);

        using var http = new HttpClient(handler);
        http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(result.TokenType, result.AccessToken); // "mtls_pop <token>"
        http.DefaultRequestHeaders.Add("x-ms-tokenboundauth", "true");           // Key Vault opt-in

        string url = $"{s.KeyVaultUrl.TrimEnd('/')}/secrets/{s.SecretName}?api-version=7.4";
        using HttpResponseMessage resp = await http.GetAsync(url);

        Ux.Info($"Key Vault responded: {(int)resp.StatusCode} {resp.StatusCode}");
        if (resp.IsSuccessStatusCode)
            Ux.Ok("Downstream Key Vault call succeeded over mTLS PoP.");
        else
            Ux.Warn("403 = RBAC (assign 'Key Vault Secrets User'); 401 = auth/binding issue.");
    }
}
