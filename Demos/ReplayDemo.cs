using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using TokenBindingShowcase;

namespace TokenBindingShowcase.Demos;

/// <summary>
/// Path 9 - Attacker replay. Paste a stolen token; this calls Key Vault with it as a plain
/// bearer (no binding certificate on the channel). A bearer token is accepted from anywhere
/// (EXFILTRATED); a bound mtls_pop token is rejected (BLOCKED, 401) because the cert is missing.
/// </summary>
public static class ReplayDemo
{
    public static async Task RunAsync(AppSettings s)
    {
        Ux.Section("[9]  Attacker replay  --  paste a stolen token and call Key Vault");
        Ux.Context(
            "Acts as an attacker on a different machine that only has the token bytes - no key, no cert.",
            "It replays the token as 'Authorization: Bearer' against the same Key Vault secret.",
            "A bearer token is accepted from anywhere; a bound (mtls_pop) token is rejected (no cert).");

        if (string.IsNullOrWhiteSpace(s.KeyVaultUrl) || string.IsNullOrWhiteSpace(s.SecretName))
        {
            Ux.Warn("Set KeyVaultUrl and SecretName first.");
            return;
        }

        Console.Write("    Paste the stolen token, then press Enter:\n    > ");
        string? token = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            Ux.Warn("No token provided.");
            return;
        }
        // If a full "<scheme> <token>" header was pasted, keep just the token bytes.
        int sp = token.IndexOf(' ');
        if (sp > 0 && sp <= 10)
            token = token[(sp + 1)..].Trim();

        DescribeToken(token);

        string url = $"{s.KeyVaultUrl.TrimEnd('/')}/secrets/{s.SecretName}?api-version=7.4";
        Ux.Info($"Replaying as Authorization: Bearer  ->  GET {url}");

        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            using HttpResponseMessage resp = await http.GetAsync(url);
            string body = await resp.Content.ReadAsStringAsync();
            int code = (int)resp.StatusCode;
            Ux.Info($"Key Vault responded: {code} {resp.StatusCode}");

            if (resp.IsSuccessStatusCode)
            {
                Ux.Danger("EXFILTRATED - the stolen token was accepted and the secret was read!");
                Ux.Takeaway("A bearer token has no binding: possession = access. This is what token binding stops.");
            }
            else if (code == 401)
            {
                Ux.Ok("BLOCKED (401) - sender-constrained token; replay rejected with no matching cert.");
                Ux.Info($"    {Trim(body, 220)}");
                Ux.Takeaway("The bound token can't be replayed from another machine - no key, no access.");
            }
            else if (code == 403)
            {
                Ux.Warn("403 - auth succeeded but this identity lacks RBAC on the secret (not a binding block).");
            }
            else
            {
                Ux.Info($"    {Trim(body, 220)}");
            }
        }
        catch (Exception ex)
        {
            Ux.Error("Replay request failed", ex);
        }
    }

    // Best-effort JWT payload peek so you can see whether the pasted token is bound.
    private static void DescribeToken(string token)
    {
        try
        {
            string[] parts = token.Split('.');
            if (parts.Length < 2)
            {
                Ux.Info("token: (not a JWT)");
                return;
            }
            string p = parts[1].Replace('-', '+').Replace('_', '/');
            switch (p.Length % 4) { case 2: p += "=="; break; case 3: p += "="; break; }

            using JsonDocument doc = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(p)));
            JsonElement r = doc.RootElement;
            string appid = r.TryGetProperty("appid", out var a) ? a.GetString() ?? "" : "(n/a)";
            bool bound = r.TryGetProperty("cnf", out _);
            Ux.Info($"token: appid={appid}, bound={(bound ? "YES (cnf claim present)" : "no (plain bearer)")}");
        }
        catch
        {
            // ignore decode errors - we still attempt the replay
        }
    }

    private static string Trim(string s, int n) => s.Length <= n ? s : s[..n] + " ...";
}
