using System.Diagnostics;
using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

/// <summary>
/// Configuration provider that retrieves secrets from GNOME Keyring via secret-tool.
/// </summary>
public class KeyringConfigurationProvider : ConfigurationProvider
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
    public KeyringConfigurationProvider(string service, string account, string configKey = "HttpsCertificatePassword")
    {
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
            string? password = FetchSecretFromKeyring(_service, _account);
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

    /// <summary>
    /// Fetches a secret from GNOME Keyring using secret-tool.
    /// </summary>
    /// <param name="service">The service name.</param>
    /// <param name="account">The account name.</param>
    /// <returns>The retrieved secret, or null if not found or on error.</returns>
    private static string? FetchSecretFromKeyring(string service, string account)
    {
        ProcessStartInfo startInfo = new()
        {
            FileName = "secret-tool",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        // Add arguments safely to avoid command injection
        startInfo.ArgumentList.Add("lookup");
        startInfo.ArgumentList.Add("service");
        startInfo.ArgumentList.Add(service);
        startInfo.ArgumentList.Add("account");
        startInfo.ArgumentList.Add(account);

        using Process? process = Process.Start(startInfo);
        if (process is null)
        {
            throw new InvalidOperationException("Failed to start secret-tool process.");
        }

        // Read output and error asynchronously to prevent deadlock
        System.Threading.Tasks.Task<string> outputTask = process.StandardOutput.ReadToEndAsync();
        System.Threading.Tasks.Task<string> errorTask = process.StandardError.ReadToEndAsync();

        // Wait for process to exit with timeout (10 seconds)
        bool exited = process.WaitForExit(10000);
        if (!exited)
        {
            process.Kill();
            throw new TimeoutException("secret-tool process timed out after 10 seconds.");
        }

        // Wait for async reads to complete
        string output = outputTask.Result;
        string error = errorTask.Result;

        if (process.ExitCode != 0)
        {
            if (!string.IsNullOrEmpty(error))
            {
                Console.Error.WriteLine($"secret-tool error: {error}");
            }
            return null;
        }

        return output.Trim();
    }
}
