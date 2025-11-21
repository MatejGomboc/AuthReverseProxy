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
    public required string Service { get; set; }

    /// <summary>
    /// Gets or sets the account name for keyring lookup.
    /// </summary>
    public required string Account { get; set; }

    /// <summary>
    /// Gets or sets the configuration key to populate with the retrieved secret.
    /// </summary>
    public required string ConfigKey { get; set; }

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
