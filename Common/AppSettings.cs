using Microsoft.Extensions.Configuration;

namespace TokenBindingShowcase;

/// <summary>
/// Strongly-typed view of the "TokenBinding" section of appsettings.json
/// (also overridable via environment variables, e.g. TokenBinding__KeyVaultUrl).
/// </summary>
public sealed class AppSettings
{
    public string KeyVaultUrl { get; set; } = "https://msidlabs.vault.azure.net/";
    public string SecretName { get; set; } = "mytbsecret";
    public string UserAssignedClientId { get; set; } = "71d22d68-0415-4801-9a68-f3916c8968d0";
    public string Resource { get; set; } = "https://vault.azure.net";
    public string Scope { get; set; } = "https://vault.azure.net/.default";
    public string AzureRegion { get; set; } = "westcentralus";
    public bool CallKeyVault { get; set; } = true;

    public bool IsUserAssigned => !string.IsNullOrWhiteSpace(UserAssignedClientId);

    public static AppSettings Load()
    {
        IConfiguration config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        var settings = new AppSettings();
        config.GetSection("TokenBinding").Bind(settings);
        return settings;
    }
}
