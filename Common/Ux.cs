using System.Security.Cryptography.X509Certificates;

namespace TokenBindingShowcase;

/// <summary>
/// Console UX: framed banner, section rules, "what's happening" context blocks,
/// takeaways, colored status lines, and a copyable full-token block.
/// </summary>
public static class Ux
{
    private const int Width = 76;

    public static void Banner(AppSettings s)
    {
        string rule = new string('=', Width);
        Console.WriteLine();
        Line(ConsoleColor.Cyan, rule);
        Line(ConsoleColor.White, "   S2S TOKEN BINDING   .   mTLS Proof-of-Possession");
        Line(ConsoleColor.Gray,  "   Managed Identity  ->  Azure Key Vault");
        Line(ConsoleColor.Cyan, rule);
        Console.WriteLine();
        Line(ConsoleColor.DarkGray, "   Acquire a Managed Identity token for Key Vault as a classic BEARER token,");
        Line(ConsoleColor.DarkGray, "   and as a token-BOUND (mTLS PoP) token three ways. A bound token is");
        Line(ConsoleColor.DarkGray, "   sender-constrained: stolen and replayed from another machine, it is rejected.");
        Console.WriteLine();
        Field("Key Vault", Or(s.KeyVaultUrl, "(unset)"));
        Field("Secret",    Or(s.SecretName, "(unset)"));
        Field("Identity",  s.IsUserAssigned ? $"user-assigned  {s.UserAssignedClientId}" : "system-assigned");
        Field("Resource",  s.Resource);
        Field("Region",    Or(s.AzureRegion, "(default)"));
        Console.WriteLine();
    }

    public static void Menu()
    {
        Console.WriteLine();
        Line(ConsoleColor.DarkCyan, "  " + new string('-', Width - 2));
        Line(ConsoleColor.White,    "  Choose a path:");
        MenuItem("1", "KeyGuard key demo", "create + list + export-fails (VBS-isolated key)", ConsoleColor.Magenta);
        MenuItem("2", "Classic MSI (v1)", "basic BEARER token via local IMDS  (stealable)", ConsoleColor.DarkYellow);
        MenuItem("3", "MSAL .NET", "BOUND mtls_pop token (+ binding certificate)", ConsoleColor.Green);
        MenuItem("4", "Microsoft Identity Web", "bound, config-driven (ProtocolScheme = MTLS_POP)", ConsoleColor.Green);
        MenuItem("5", "Azure Key Vault SDK", "ManagedIdentityCredential + SecretClient", ConsoleColor.Green);
        MenuItem("6", "Run the bound paths", "3, 4 and 5 in sequence", ConsoleColor.Green);
        MenuItem("0", "Exit", "", ConsoleColor.Gray);
        Line(ConsoleColor.DarkCyan, "  " + new string('-', Width - 2));
        Console.Write("  > ");
    }

    /// <summary>A titled section rule for a path.</summary>
    public static void Section(string label)
    {
        Console.WriteLine();
        Line(ConsoleColor.DarkCyan, "  +" + new string('-', Width - 3));
        Line(ConsoleColor.Cyan,     "  |  " + label);
        Line(ConsoleColor.DarkCyan, "  +" + new string('-', Width - 3));
    }

    /// <summary>A "what's happening" explanation block under a section.</summary>
    public static void Context(params string[] lines)
    {
        Line(ConsoleColor.DarkGray, "    .--- what's happening");
        foreach (string l in lines)
            Line(ConsoleColor.Gray, "    |  " + l);
        Line(ConsoleColor.DarkGray, "    '---");
        Console.WriteLine();
    }

    /// <summary>A highlighted one-line conclusion after a path runs.</summary>
    public static void Takeaway(string line)
    {
        Console.WriteLine();
        Line(ConsoleColor.Green, "    >> " + line);
    }

    public static void Ok(string msg)   => Line(ConsoleColor.Green,      "    [ OK ]  " + msg);
    public static void Info(string msg) => Line(ConsoleColor.Gray,       "    .       " + msg);
    public static void Warn(string msg) => Line(ConsoleColor.DarkYellow, "    [ !  ]  " + msg);

    public static void Error(string msg, Exception ex)
    {
        Line(ConsoleColor.Red, "    [ERR ]  " + msg + ":");
        Line(ConsoleColor.Red, "            " + ex.GetType().Name + " - " + ex.Message);
    }

    /// <summary>Prints the key facts of an acquired token, then the full token for replay.</summary>
    public static void PrintToken(string tokenType, string accessToken, DateTimeOffset expiresOn, X509Certificate2? bindingCert)
    {
        Ok($"Token acquired   token_type = {tokenType}");
        Info($"expires_on    = {expiresOn:u}");
        if (bindingCert is not null)
            Info($"binding cert  = {bindingCert.Thumbprint}");
        else
            Warn("No binding certificate -> bearer token (or host without KeyGuard).");
        PrintFullToken(tokenType, accessToken);
    }

    /// <summary>
    /// Prints the FULL access token on its own (unindented) line so it can be copied and
    /// replayed from another machine - the bearer-vs-bound theft/replay demo.
    /// </summary>
    public static void PrintFullToken(string tokenType, string accessToken)
    {
        Console.WriteLine();
        Line(ConsoleColor.DarkGray, "    .----- ACCESS TOKEN  (scheme: " + tokenType + ")  -- copy to replay on another VM");
        Console.WriteLine(string.IsNullOrEmpty(accessToken) ? "(none)" : accessToken);
        Line(ConsoleColor.DarkGray, "    '----- end token");
        Console.WriteLine();
    }

    // ---- helpers ----
    private static void Field(string key, string value)
    {
        ConsoleColor p = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.DarkGray; Console.Write("   " + key.PadRight(9) + " : ");
        Console.ForegroundColor = ConsoleColor.Gray;     Console.WriteLine(value);
        Console.ForegroundColor = p;
    }

    private static void MenuItem(string key, string name, string desc, ConsoleColor keyColor)
    {
        ConsoleColor p = Console.ForegroundColor;
        Console.ForegroundColor = keyColor;            Console.Write("    " + key + ")  ");
        Console.ForegroundColor = ConsoleColor.White;  Console.Write(name.PadRight(24));
        Console.ForegroundColor = ConsoleColor.DarkGray; Console.WriteLine(desc);
        Console.ForegroundColor = p;
    }

    private static string Or(string value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;

    private static void Line(ConsoleColor color, string text)
    {
        ConsoleColor p = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ForegroundColor = p;
    }
}
