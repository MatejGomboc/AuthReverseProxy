using System.Runtime.InteropServices;
using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

/// <summary>
/// Configuration provider that retrieves secrets from GNOME Keyring via libsecret.
/// </summary>
public class KeyringConfigurationProvider : ConfigurationProvider
{
    private const string LibSecret = "libsecret-1.so.0";
    private const string LibGLib = "libglib-2.0.so.0";

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
        // Create GHashTable for attributes - we'll manage memory manually
        IntPtr attributes = g_hash_table_new_full(
            g_str_hash(),
            g_str_equal(),
            IntPtr.Zero,  // key_destroy_func - NULL, we'll free manually
            IntPtr.Zero); // value_destroy_func - NULL, we'll free manually

        if (attributes == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to create GHashTable for attributes.");
        }

        // Track allocated strings for cleanup
        IntPtr serviceKey = IntPtr.Zero;
        IntPtr serviceValue = IntPtr.Zero;
        IntPtr accountKey = IntPtr.Zero;
        IntPtr accountValue = IntPtr.Zero;

        try
        {
            // Add service attribute using g_strdup
            serviceKey = g_strdup("service");
            serviceValue = g_strdup(service);
            g_hash_table_insert(attributes, serviceKey, serviceValue);

            // Add account attribute using g_strdup
            accountKey = g_strdup("account");
            accountValue = g_strdup(account);
            g_hash_table_insert(attributes, accountKey, accountValue);

            IntPtr error = IntPtr.Zero;

            // Use lookupv which takes a GHashTable (more reliable than variadic version)
            IntPtr passwordPtr = secret_password_lookupv_sync(
                IntPtr.Zero,     // schema (NULL = generic)
                attributes,      // attribute hash table
                IntPtr.Zero,     // cancellable (NULL = no cancellation)
                out error);      // error output

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
        finally
        {
            // Wrap ALL cleanup in try-catch to ensure we attempt all cleanup
            // even if one operation fails, and to avoid masking original exceptions
            try
            {
                // Clean up the hash table first (removes references to our strings)
                g_hash_table_destroy(attributes);
            }
            catch
            {
                // Suppress hash table cleanup exceptions
            }

            try
            {
                // Now manually free the strings we allocated with g_strdup
                if (serviceKey != IntPtr.Zero) g_free(serviceKey);
            }
            catch
            {
                // Suppress g_free exceptions
            }

            try
            {
                if (serviceValue != IntPtr.Zero) g_free(serviceValue);
            }
            catch
            {
                // Suppress g_free exceptions
            }

            try
            {
                if (accountKey != IntPtr.Zero) g_free(accountKey);
            }
            catch
            {
                // Suppress g_free exceptions
            }

            try
            {
                if (accountValue != IntPtr.Zero) g_free(accountValue);
            }
            catch
            {
                // Suppress g_free exceptions
            }
        }
    }

    /// <summary>
    /// Extracts error message from GError structure.
    /// </summary>
    private static string? GetGErrorMessage(IntPtr error)
    {
        if (error == IntPtr.Zero)
            return null;

        // GError structure: { GQuark domain (4 bytes); gint code (4 bytes); gchar *message (pointer); }
        // Message pointer is at offset 8 on both 32-bit and 64-bit systems
        IntPtr messagePtr = Marshal.ReadIntPtr(error, 8);
        return Marshal.PtrToStringUTF8(messagePtr);
    }

    #region P/Invoke Declarations

    /// <summary>
    /// Lookup a password using attributes hash table (non-variadic, more reliable).
    /// </summary>
    [DllImport(LibSecret, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr secret_password_lookupv_sync(
        IntPtr schema,
        IntPtr attributes,
        IntPtr cancellable,
        out IntPtr error);

    /// <summary>
    /// Free a password retrieved from the secret service.
    /// </summary>
    [DllImport(LibSecret, CallingConvention = CallingConvention.Cdecl)]
    private static extern void secret_password_free(IntPtr password);

    /// <summary>
    /// Free a GError structure.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void g_error_free(IntPtr error);

    /// <summary>
    /// Create a new GHashTable.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr g_hash_table_new_full(
        IntPtr hash_func,
        IntPtr key_equal_func,
        IntPtr key_destroy_func,
        IntPtr value_destroy_func);

    /// <summary>
    /// Insert a key-value pair into GHashTable.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void g_hash_table_insert(IntPtr hash_table, IntPtr key, IntPtr value);

    /// <summary>
    /// Destroy a GHashTable.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void g_hash_table_destroy(IntPtr hash_table);

    /// <summary>
    /// GLib string hash function pointer.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "g_str_hash")]
    private static extern IntPtr g_str_hash();

    /// <summary>
    /// GLib string equality function pointer.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "g_str_equal")]
    private static extern IntPtr g_str_equal();

    /// <summary>
    /// Duplicate a string using GLib allocator (handles UTF-8 correctly).
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr g_strdup([MarshalAs(UnmanagedType.LPUTF8Str)] string str);

    /// <summary>
    /// Free memory allocated by GLib.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void g_free(IntPtr mem);

    #endregion
}
