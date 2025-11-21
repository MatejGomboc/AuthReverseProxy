using System.Runtime.InteropServices;
using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

/// <summary>
/// Configuration provider that retrieves secrets from GNOME Keyring via libsecret.
/// </summary>
public class KeyringConfigurationProvider : ConfigurationProvider
{
    private const string LibSecret = "libsecret-1.so.0";

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
    /// Fetches a secret from GNOME Keyring using libsecret.
    /// </summary>
    /// <param name="service">The service name.</param>
    /// <param name="account">The account name.</param>
    /// <returns>The retrieved secret, or null if not found or on error.</returns>
    private static string? FetchSecretFromKeyring(string service, string account)
    {
        IntPtr error = IntPtr.Zero;

        // Lookup password with service and account attributes
        // NULL schema means use simple attribute matching
        IntPtr passwordPtr = secret_password_lookup_sync(
            IntPtr.Zero,        // schema (NULL = use attributes)
            IntPtr.Zero,        // cancellable (NULL = no cancellation)
            out error,          // error output
            "service", service, // first attribute key-value pair
            "account", account, // second attribute key-value pair
            IntPtr.Zero);       // NULL terminator for variadic args

        // Check for errors
        if (error != IntPtr.Zero)
        {
            string? errorMessage = GetGErrorMessage(error);
            g_error_free(error);
            throw new InvalidOperationException($"libsecret error: {errorMessage ?? "Unknown error"}");
        }

        // No password found
        if (passwordPtr == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            // Marshal UTF-8 string from native memory
            return Marshal.PtrToStringUTF8(passwordPtr);
        }
        finally
        {
            // Always free the password memory
            secret_password_free(passwordPtr);
        }
    }

    /// <summary>
    /// Extracts error message from GError structure.
    /// </summary>
    private static string? GetGErrorMessage(IntPtr error)
    {
        if (error == IntPtr.Zero)
            return null;

        // GError structure: { GQuark domain; gint code; gchar *message; }
        // Read the message pointer (3rd field, at offset 8 on 64-bit)
        IntPtr messagePtr = Marshal.ReadIntPtr(error, IntPtr.Size * 2);
        return Marshal.PtrToStringUTF8(messagePtr);
    }

    #region P/Invoke Declarations

    /// <summary>
    /// Lookup a password in the secret service.
    /// </summary>
    [DllImport(LibSecret, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr secret_password_lookup_sync(
        IntPtr schema,
        IntPtr cancellable,
        out IntPtr error,
        string attribute1_name,
        string attribute1_value,
        string attribute2_name,
        string attribute2_value,
        IntPtr end);

    /// <summary>
    /// Free a password retrieved from the secret service.
    /// </summary>
    [DllImport(LibSecret, CallingConvention = CallingConvention.Cdecl)]
    private static extern void secret_password_free(IntPtr password);

    /// <summary>
    /// Free a GError structure.
    /// </summary>
    [DllImport("libglib-2.0.so.0", CallingConvention = CallingConvention.Cdecl)]
    private static extern void g_error_free(IntPtr error);

    #endregion
}
