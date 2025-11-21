using System.Runtime.InteropServices;
using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

/// <summary>
/// Configuration provider that retrieves secrets from GNOME Keyring via libsecret.
/// Uses GHashTable-based API to avoid variadic function complexity and ensure type safety.
/// </summary>
public sealed class KeyringConfigurationProvider : ConfigurationProvider
{
    private const string LibSecret = "libsecret-1.so.0";
    private const string LibGLib = "libglib-2.0.so.0";

    private readonly string _service;
    private readonly string _account;
    private readonly string _configKey;

    // Cache delegate instances to prevent garbage collection
    private static readonly GStrHashDelegate _gStrHashDelegate = g_str_hash;
    private static readonly GStrEqualDelegate _gStrEqualDelegate = g_str_equal;

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
            throw new ArgumentNullException(nameof(service));
        if (account is null)
            throw new ArgumentNullException(nameof(account));
        if (configKey is null)
            throw new ArgumentNullException(nameof(configKey));

        if (string.IsNullOrWhiteSpace(service))
            throw new ArgumentException("Service name cannot be empty or whitespace.", nameof(service));
        if (string.IsNullOrWhiteSpace(account))
            throw new ArgumentException("Account name cannot be empty or whitespace.", nameof(account));
        if (string.IsNullOrWhiteSpace(configKey))
            throw new ArgumentException("Config key cannot be empty or whitespace.", nameof(configKey));

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
        catch (DllNotFoundException ex)
        {
            string message = $"Required library not found: {ex.Message}. Ensure libsecret-1 and libglib-2.0 are installed.";
            Console.Error.WriteLine($"Error: {message}");
            throw new InvalidOperationException(message, ex);
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
    /// <returns>The retrieved secret, or null if not found.</returns>
    private static string? FetchSecretFromKeyring(string service, string account)
    {
        // Get function pointers for GHashTable creation
        // We keep delegate instances alive in static fields to prevent GC
        IntPtr gStrHashFunc = Marshal.GetFunctionPointerForDelegate(_gStrHashDelegate);
        IntPtr gStrEqualFunc = Marshal.GetFunctionPointerForDelegate(_gStrEqualDelegate);

        if (gStrHashFunc == IntPtr.Zero || gStrEqualFunc == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to get GLib string function pointers.");
        }

        // Create GHashTable for attributes
        IntPtr attributes = g_hash_table_new_full(
            gStrHashFunc,
            gStrEqualFunc,
            IntPtr.Zero,  // key_destroy_func - NULL (we manage memory)
            IntPtr.Zero); // value_destroy_func - NULL (we manage memory)

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
            // Allocate and insert service attribute
            serviceKey = g_strdup("service");
            if (serviceKey == IntPtr.Zero)
                throw new OutOfMemoryException("Failed to allocate memory for 'service' key.");

            serviceValue = g_strdup(service);
            if (serviceValue == IntPtr.Zero)
                throw new OutOfMemoryException($"Failed to allocate memory for service value '{service}'.");

            g_hash_table_insert(attributes, serviceKey, serviceValue);

            // Allocate and insert account attribute
            accountKey = g_strdup("account");
            if (accountKey == IntPtr.Zero)
                throw new OutOfMemoryException("Failed to allocate memory for 'account' key.");

            accountValue = g_strdup(account);
            if (accountValue == IntPtr.Zero)
                throw new OutOfMemoryException($"Failed to allocate memory for account value '{account}'.");

            g_hash_table_insert(attributes, accountKey, accountValue);

            // Lookup password using the attribute hash table
            IntPtr passwordPtr = secret_password_lookupv_sync(
                IntPtr.Zero,     // schema (NULL = generic schema)
                attributes,      // attribute hash table
                IntPtr.Zero,     // cancellable (NULL = no cancellation)
                out IntPtr error); // error output

            // Check for errors
            if (error != IntPtr.Zero)
            {
                string? errorMessage = GetGErrorMessage(error);
                g_error_free(error);
                throw new InvalidOperationException($"libsecret error: {errorMessage ?? "Unknown error"}");
            }

            // No password found (not an error, just no matching entry)
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
            // Clean up all allocated resources in reverse order
            // Use individual try-catch to ensure all cleanups are attempted
            
            if (attributes != IntPtr.Zero)
            {
                try { g_hash_table_destroy(attributes); }
                catch { /* Suppress cleanup exceptions */ }
            }

            if (accountValue != IntPtr.Zero)
            {
                try { g_free(accountValue); }
                catch { /* Suppress cleanup exceptions */ }
            }

            if (accountKey != IntPtr.Zero)
            {
                try { g_free(accountKey); }
                catch { /* Suppress cleanup exceptions */ }
            }

            if (serviceValue != IntPtr.Zero)
            {
                try { g_free(serviceValue); }
                catch { /* Suppress cleanup exceptions */ }
            }

            if (serviceKey != IntPtr.Zero)
            {
                try { g_free(serviceKey); }
                catch { /* Suppress cleanup exceptions */ }
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

        try
        {
            // Use Marshal.PtrToStructure for safe, portable access
            GErrorStruct gError = Marshal.PtrToStructure<GErrorStruct>(error);
            
            if (gError.message == IntPtr.Zero)
                return null;
            
            return Marshal.PtrToStringUTF8(gError.message);
        }
        catch
        {
            return null;
        }
    }

    #region Structures and Delegates

    /// <summary>
    /// GError structure definition with proper layout.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct GErrorStruct
    {
        public uint domain;      // GQuark (guint32)
        public int code;         // gint (gint32)
        public IntPtr message;   // gchar* - marshaler handles padding correctly
    }

    /// <summary>
    /// Delegate for GLib string hash function.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint GStrHashDelegate(IntPtr str);

    /// <summary>
    /// Delegate for GLib string equality function.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I4)]
    private delegate bool GStrEqualDelegate(IntPtr a, IntPtr b);

    #endregion

    #region P/Invoke Declarations

    /// <summary>
    /// Lookup a password using attributes hash table.
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
    /// Duplicate a string using GLib allocator (handles UTF-8 correctly).
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr g_strdup([MarshalAs(UnmanagedType.LPUTF8Str)] string str);

    /// <summary>
    /// Free memory allocated by GLib.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl)]
    private static extern void g_free(IntPtr mem);

    /// <summary>
    /// GLib string hash function.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "g_str_hash")]
    private static extern uint g_str_hash(IntPtr str);

    /// <summary>
    /// GLib string equality function.
    /// </summary>
    [DllImport(LibGLib, CallingConvention = CallingConvention.Cdecl, EntryPoint = "g_str_equal")]
    [return: MarshalAs(UnmanagedType.I4)]
    private static extern bool g_str_equal(IntPtr a, IntPtr b);

    #endregion
}
