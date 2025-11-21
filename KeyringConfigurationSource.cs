using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

/// <summary>
/// Configuration source for retrieving secrets from GNOME Keyring.
/// </summary>
public class KeyringConfigurationSource : IConfigurationSource
{
    /// <summary>
    /// Gets or sets the service name for keyring lookup.
    /// </summary>
    public string Service { get; set; } = "AuthReverseProxy";

    /// <summary>
    /// Gets or sets the account name for keyring lookup.
    /// </summary>
    public string Account { get; set; } = "certificate-default";

    /// <summary>
    /// Gets or sets the configuration key to populate with the retrieved secret.
    /// </summary>
    public string ConfigKey { get; set; } = "CertificatePassword";

    /// <summary>
    /// Builds the configuration provider.
    /// </summary>
    /// <param name="builder">The configuration builder.</param>
    /// <returns>A new instance of <see cref="KeyringConfigurationProvider"/>.</returns>
    public IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        return new KeyringConfigurationProvider(Service, Account, ConfigKey);
    }
}
