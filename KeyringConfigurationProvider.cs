using System;
using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

/// <summary>
/// Configuration provider that retrieves secrets from GNOME Keyring via libsecret.
/// </summary>
public sealed class KeyringConfigurationProvider : ConfigurationProvider
{
    private readonly string _service;
    private readonly string _account;
    private readonly string _configKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyringConfigurationProvider"/> class.
    /// </summary>
    /// <param name="service">The service name for keyring lookup.</param>
    /// <param name="account">The account name for keyring lookup.</param>
    /// <param name="configKey">The configuration key to populate with the retrieved secret.</param>
    /// <exception cref="ArgumentNullException">Thrown when service, account, or configKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown when service, account, or configKey is empty or whitespace.</exception>
    public KeyringConfigurationProvider(string service, string account, string configKey)
    {
        if (service is null)
        {
            throw new ArgumentNullException(nameof(service));
        }

        if (account is null)
        {
            throw new ArgumentNullException(nameof(account));
        }

        if (configKey is null)
        {
            throw new ArgumentNullException(nameof(configKey));
        }

        if (string.IsNullOrWhiteSpace(service))
        {
            throw new ArgumentException("Service name cannot be empty or whitespace.", nameof(service));
        }

        if (string.IsNullOrWhiteSpace(account))
        {
            throw new ArgumentException("Account name cannot be empty or whitespace.", nameof(account));
        }

        if (string.IsNullOrWhiteSpace(configKey))
        {
            throw new ArgumentException("Config key cannot be empty or whitespace.", nameof(configKey));
        }

        _service = service;
        _account = account;
        _configKey = configKey;
    }

    /// <summary>
    /// Loads the secret from the keyring into the configuration data.
    /// </summary>
    public override void Load()
    {
        try
        {
            string? password = GnomeKeyring.GetSecret(_service, _account);

            if (!string.IsNullOrEmpty(password))
            {
                Data[_configKey] = password;
            }
            else
            {
                Console.Error.WriteLine($"Warning: No secret found in keyring for service '{_service}', account '{_account}'.");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error retrieving secret from keyring: {ex.Message}");
            throw;
        }
    }
}
