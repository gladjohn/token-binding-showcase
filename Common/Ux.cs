using System.Security.Cryptography.X509Certificates;

namespace TokenBindingShowcase;

/// <summary>Tiny console UX helpers (banner, menu, colored status lines).</summary>
public static class Ux
{
    public static void Banner(AppSettings s)
    {
        Line(ConsoleColor.Cyan, "==================================================================");
        Line(ConsoleColor.Cyan, "  S2S Token Binding (mTLS PoP) - Managed Identity showcase");
        Line(ConsoleColor.Cyan, "  MSAL  .  Microsoft Identity Web  .  Azure Key Vault SDK");
        Line(ConsoleColor.Cyan, "==================================================================");
        Console.WriteLine();
        Console.WriteLine($"  Key Vault : {Or(s.KeyVaultUrl, "(set TokenBinding:KeyVaultUrl in appsettings.json)")}");
        Console.WriteLine($"  Secret    : {Or(s.SecretName, "(set TokenBinding:SecretName)")}");
        Console.WriteLine($"  Identity  : {(s.IsUserAssigned ? $"user-assigned {s.UserAssignedClientId}" : "system-assigned")}");
        Console.WriteLine($"  Resource  : {s.Resource}");
        Console.WriteLine();
    }

    public static void Menu()
    {
        Console.WriteLine("Choose a token-acquisition path:");
        Console.WriteLine("  1) MSAL .NET              (ManagedIdentityApplication + WithMtlsProofOfPossession + WithAttestationSupport)");
        Console.WriteLine("  2) Microsoft Identity Web (IDownstreamApi, ProtocolScheme = MTLS_POP)");
        Console.WriteLine("  3) Azure Key Vault SDK    (ManagedIdentityCredential + SecretClient)");
        Console.WriteLine("  4) Run all three");
        Console.Write("> ");
    }

    public static void Header(string title)
    {
        Console.WriteLine();
        string dashes = new string('-', Math.Max(3, 62 - title.Length));
        Line(ConsoleColor.Yellow, $"---- {title} {dashes}");
    }

    public static void Ok(string msg) => Line(ConsoleColor.Green, "  [ OK ] " + msg);
    public static void Info(string msg) => Line(ConsoleColor.Gray, "         " + msg);
    public static void Warn(string msg) => Line(ConsoleColor.DarkYellow, "  [ !  ] " + msg);

    public static void Error(string msg, Exception ex)
    {
        Line(ConsoleColor.Red, "  [ERR ] " + msg + ": " + ex.GetType().Name);
        Line(ConsoleColor.Red, "         " + ex.Message);
    }

    /// <summary>Prints the key facts of an acquired token (type, expiry, binding cert).</summary>
    public static void PrintToken(string tokenType, string accessToken, DateTimeOffset expiresOn, X509Certificate2? bindingCert)
    {
        Ok($"Token acquired. token_type = {tokenType}");
        Info($"expires_on   = {expiresOn:u}");
        Info($"access_token = {Truncate(accessToken)}");
        if (bindingCert is not null)
            Info($"binding cert = {bindingCert.Thumbprint}  (subject {bindingCert.Subject})");
        else
            Warn("No binding certificate on the result -> bearer token (or host without KeyGuard).");
    }

    private static string Truncate(string s) =>
        string.IsNullOrEmpty(s) ? "(none)" : (s.Length <= 24 ? s : s[..12] + "..." + s[^6..]);

    private static string Or(string value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;

    private static void Line(ConsoleColor color, string text)
    {
        ConsoleColor prev = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ForegroundColor = prev;
    }
}
