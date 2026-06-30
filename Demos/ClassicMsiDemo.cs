using System.Text.Json;
using TokenBindingShowcase;

namespace TokenBindingShowcase.Demos;

/// <summary>
/// Path 1 - Classic Managed Identity (v1). A single raw call to the local IMDS endpoint
/// returns a plain BEARER token - the "before" picture: simple, but stealable / replayable.
/// </summary>
public static class ClassicMsiDemo
{
    public static async Task RunAsync(AppSettings s)
    {
        Ux.Section("[2]  Classic Managed Identity (v1)  --  basic BEARER token");
        Ux.Context(
            "The 'before' picture: one local call to the IMDS endpoint returns an access token.",
            "No key, no certificate, no attestation -- just a plain BEARER token.",
            "A bearer token is portable: whoever holds it can use it from anywhere.");

        string url = "http://169.254.169.254/metadata/identity/oauth2/token"
                   + "?api-version=2018-02-01&resource=" + Uri.EscapeDataString(s.Resource);
        if (s.IsUserAssigned)
            url += "&client_id=" + Uri.EscapeDataString(s.UserAssignedClientId);

        Ux.Info($"GET {url}");
        Ux.Info("Metadata: true");

        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            http.DefaultRequestHeaders.Add("Metadata", "true");

            using HttpResponseMessage resp = await http.GetAsync(url);
            string body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
            {
                Ux.Warn($"IMDS returned {(int)resp.StatusCode} {resp.StatusCode}: {body}");
                return;
            }

            using JsonDocument doc = JsonDocument.Parse(body);
            JsonElement root = doc.RootElement;
            string token = root.TryGetProperty("access_token", out var at) ? at.GetString() ?? "" : "";
            string type = root.TryGetProperty("token_type", out var tt) ? tt.GetString() ?? "Bearer" : "Bearer";

            Ux.Ok($"token_type = {type}   (UNBOUND -> replayable from any machine)");
            Ux.PrintFullToken(type, token);
            Ux.Takeaway("This token is UNBOUND -- copy it and it works from any machine. That is the risk token binding removes.");
        }
        catch (Exception ex)
        {
            Ux.Error("Classic IMDS call failed (run on an Azure VM that has a managed identity)", ex);
        }
    }
}
