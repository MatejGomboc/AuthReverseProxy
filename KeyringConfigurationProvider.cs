using System.Runtime.InteropServices;
using System.Text;
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
        // Get GLib's free function pointer for proper cleanup
        IntPtr gFreeFunc = g_free_ptr();

        // Create GHashTable for attributes with g_free as destroyer
        IntPtr attributes = g_hash_table_new_full(
            g_str_hash(),
            g_str_equal(),
            gFreeFunc,  // key_destroy_func - will call g_free on keys
            gFreeFunc); // value_destroy_func - will call g_free on values

        if (attributes == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to create GHashTable for attributes.");
        }

        try
        {
            // Add service attribute
            IntPtr serviceKey = MarshalUtf8String("service");
            IntPtr serviceValue = MarshalUtf8String(service);
            g_hash_table_insert(attributes, serviceKey, serviceValue);

            // Add account attribute
            IntPtr accountKey = MarshalUtf8String("account");
            IntPtr accountValue = MarshalUtf8String(account);
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
            // Clean up the hash table (will automatically free all keys and values via g_free)
            g_hash_table_destroy(attributes);
        }
    }

    /// <summary>
    /// Marshal a .NET string to UTF-8 native string using GLib's allocator.
    /// </summary>
    private static IntPtr MarshalUtf8String(string str)
    {
        byte[] utf8Bytes = Encoding.UTF8.GetBytes(str + "\0"); // null-terminated
        IntPtr ptr = g_malloc(utf8Bytes.Length);
        Marshal.Copy(utf8Bytes, 0, ptr, utf8Bytes.Length);
        return ptr;
    }

    /// <summary>
    /// Extracts error message from GError structure.
    /// </summary>
    private static string? GetGErrorMessage(IntPtr error)
    {
        if (error == IntPtr.Zero)
            return null;

        // GError structure: { GQuark domain (4 bytes); gint code (4 bytes); gchar *message (pointer); }
        // On 64-bit: message pointer is at offset 8 (after 4-byte domain and 4-byte code)
        // On 32-bit: message pointer is at offset 8 (same layout)
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
    /// GLib memory allocator.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr g_malloc(int size);

    /// <summary>
    /// GLib free function pointer (for use as destroy function).
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "g_free")]
    private static extern IntPtr g_free_ptr();

    #endregion
}
