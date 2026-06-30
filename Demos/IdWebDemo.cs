using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;
using TokenBindingShowcase;

namespace TokenBindingShowcase.Demos;

/// <summary>
/// Path 2 - Microsoft Identity Web. The "AzureKeyVault" downstream API is configured in
/// code from <see cref="AppSettings"/> (ProtocolScheme = MTLS_POP + Managed Identity), so the
/// single exe is self-contained. IDownstreamApi handles acquisition, the binding certificate,
/// and the mutual-TLS call.
/// </summary>
public static class IdWebDemo
{
    private static IServiceProvider? _provider;

    public static async Task RunAsync(AppSettings s)
    {
        Ux.Section("[4]  Microsoft Identity Web  --  bound, config-driven");
        Ux.Context(
            "Same binding as MSAL, but driven by configuration -- no mTLS plumbing in your code.",
            "ProtocolScheme = MTLS_POP tells IDownstreamApi to acquire the bound token, attach the",
            "binding certificate, add the Key Vault opt-in header, and make the call over mTLS.");

        try
        {
            IDownstreamApi api = GetProvider(s).GetRequiredService<IDownstreamApi>();

            Ux.Info("IDownstreamApi.CallApiForAppAsync(\"AzureKeyVault\")  (config-driven MI + MTLS_POP)");

            using HttpResponseMessage resp = await api.CallApiForAppAsync("AzureKeyVault");

            Ux.Info($"Key Vault responded: {(int)resp.StatusCode} {resp.StatusCode}");
            if (resp.IsSuccessStatusCode)
                Ux.Ok("Downstream Key Vault call succeeded (Identity Web did acquisition + mTLS).");
            else
                Ux.Warn("403 = RBAC (assign 'Key Vault Secrets User'); 401 = auth/binding issue.");

            Ux.Takeaway("Same bound result as MSAL -- but you only wrote configuration.");
        }
        catch (Exception ex)
        {
            Ux.Error("Identity Web downstream call failed (expected off a KeyGuard-enabled VM)", ex);
        }
    }

    // TokenAcquirerFactory.GetDefaultInstance() is a process singleton whose Build() may be
    // called only once - so build the provider lazily and reuse it across menu iterations.
    private static IServiceProvider GetProvider(AppSettings s)
    {
        if (_provider is not null)
            return _provider;

        TokenAcquirerFactory factory = TokenAcquirerFactory.GetDefaultInstance();
        factory.Services.AddDownstreamApi("AzureKeyVault", options =>
        {
            options.BaseUrl = s.KeyVaultUrl;
            options.RelativePath = $"secrets/{s.SecretName}?api-version=7.4";
            options.Scopes = new[] { s.Scope };
            options.RequestAppToken = true;
            options.ProtocolScheme = "MTLS_POP";
            options.AcquireTokenOptions.ManagedIdentity = new ManagedIdentityOptions
            {
                UserAssignedClientId = s.IsUserAssigned ? s.UserAssignedClientId : null
            };
            // Key Vault opt-in header for token-bound auth (the MSAL path sets this too).
            options.CustomizeHttpRequestMessage = request =>
                request.Headers.TryAddWithoutValidation("x-ms-tokenboundauth", "true");
        });
        _provider = factory.Build();
        return _provider;
    }
}
