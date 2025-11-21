using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

/// <summary>
/// Extension methods for adding keyring configuration support to <see cref="IConfigurationBuilder"/>.
/// </summary>
public static class KeyringConfigurationExtensions
{
    /// <summary>
    /// Adds GNOME Keyring as a configuration source.
    /// </summary>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="service">The service name for keyring lookup. Defaults to "AuthReverseProxy".</param>
    /// <param name="account">The account name for keyring lookup. Defaults to "certificate-default".</param>
    /// <param name="configKey">The configuration key to populate. Defaults to "CertificatePassword".</param>
    /// <returns>The configuration builder for method chaining.</returns>
    public static IConfigurationBuilder AddKeyring(
        this IConfigurationBuilder builder,
        string service = "AuthReverseProxy",
        string account = "certificate-default",
        string configKey = "CertificatePassword")
    {
        return builder.Add(new KeyringConfigurationSource
        {
            Service = service,
            Account = account,
            ConfigKey = configKey
        });
    }
}
