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
        Console.WriteLine("Choose a path:");
        Console.WriteLine("  1) Classic MSI (v1)        basic BEARER token via local IMDS  (stealable / replayable)");
        Console.WriteLine("  2) MSAL .NET               BOUND mtls_pop token (+ binding cert)");
        Console.WriteLine("  3) Microsoft Identity Web  bound, config-driven (ProtocolScheme = MTLS_POP)");
        Console.WriteLine("  4) Azure Key Vault SDK     ManagedIdentityCredential + SecretClient");
        Console.WriteLine("  5) Run the bound paths (2, 3, 4)");
        Console.WriteLine("  0) Exit");
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

    /// <summary>Prints the key facts of an acquired token, then the full token for replay.</summary>
    public static void PrintToken(string tokenType, string accessToken, DateTimeOffset expiresOn, X509Certificate2? bindingCert)
    {
        Ok($"Token acquired. token_type = {tokenType}");
        Info($"expires_on   = {expiresOn:u}");
        if (bindingCert is not null)
            Info($"binding cert = {bindingCert.Thumbprint}  (subject {bindingCert.Subject})");
        else
            Warn("No binding certificate -> bearer token (or host without KeyGuard).");
        PrintFullToken(tokenType, accessToken);
    }

    /// <summary>
    /// Prints the FULL access token on its own line so it can be copied and replayed
    /// from another machine (the bearer-vs-bound theft/replay demo).
    /// </summary>
    public static void PrintFullToken(string tokenType, string accessToken)
    {
        Console.WriteLine();
        Line(ConsoleColor.DarkGray, $"  ===== ACCESS TOKEN  (scheme: {tokenType})  -- copy to replay on another VM =====");
        Console.WriteLine(string.IsNullOrEmpty(accessToken) ? "(none)" : accessToken);
        Line(ConsoleColor.DarkGray,  "  ============================================================================");
        Console.WriteLine();
    }

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
