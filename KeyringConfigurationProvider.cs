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

    // Cache function pointers (loaded once, kept for application lifetime)
    // Note: We intentionally keep the GLib library loaded because these function
    // pointers remain valid only while the library is loaded. For a long-running
    // server process, this is the correct approach.
    private static IntPtr _gStrHashPtr;
    private static IntPtr _gStrEqualPtr;
    private static readonly object _functionPointerLock = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyringConfigurationProvider"/> class.
    /// </summary>
    /// <param name="service">The service name for keyring lookup.</param>
    /// <param name="account">The account name for keyring lookup.</param>
    /// <param name="configKey">The configuration key to populate with the retrieved secret.</param>
    /// <exception cref="ArgumentException">Thrown when service or account is null or whitespace.</exception>
    public KeyringConfigurationProvider(string service, string account, string configKey = "HttpsCertificatePassword")
    {
        if (string.IsNullOrWhiteSpace(service))
            throw new ArgumentException("Service name cannot be null or whitespace.", nameof(service));
        
        if (string.IsNullOrWhiteSpace(account))
            throw new ArgumentException("Account name cannot be null or whitespace.", nameof(account));
        
        if (string.IsNullOrWhiteSpace(configKey))
            throw new ArgumentException("Config key cannot be null or whitespace.", nameof(configKey));

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
    /// Initializes GLib function pointers (called once, thread-safe).
    /// </summary>
    private static void InitializeGLibFunctionPointers()
    {
        if (_gStrHashPtr != IntPtr.Zero && _gStrEqualPtr != IntPtr.Zero)
            return;

        lock (_functionPointerLock)
        {
            // Double-checked locking
            if (_gStrHashPtr != IntPtr.Zero && _gStrEqualPtr != IntPtr.Zero)
                return;

            IntPtr libHandle = IntPtr.Zero;

            try
            {
                // Open GLib library
                // Note: We intentionally do not close this library handle. The function pointers
                // we obtain remain valid only while the library is loaded, and we cache them
                // for the lifetime of the application. For a long-running server, keeping the
                // library loaded is the correct approach.
                libHandle = dlopen(LibGLib, RTLD_LAZY);
                if (libHandle == IntPtr.Zero)
                {
                    IntPtr error = dlerror();
                    string? errorMsg = error != IntPtr.Zero ? Marshal.PtrToStringUTF8(error) : "Unknown error";
                    throw new InvalidOperationException($"Failed to load {LibGLib}: {errorMsg}");
                }

                // Clear any existing error
                dlerror();

                // Get g_str_hash pointer
                IntPtr gStrHashPtr = dlsym(libHandle, "g_str_hash");
                IntPtr error1 = dlerror();
                if (error1 != IntPtr.Zero)
                {
                    string? errorMsg = Marshal.PtrToStringUTF8(error1);
                    dlclose(libHandle);
                    throw new InvalidOperationException($"Failed to find g_str_hash symbol: {errorMsg}");
                }

                if (gStrHashPtr == IntPtr.Zero)
                {
                    dlclose(libHandle);
                    throw new InvalidOperationException("g_str_hash symbol pointer is null");
                }

                // Clear error again
                dlerror();

                // Get g_str_equal pointer
                IntPtr gStrEqualPtr = dlsym(libHandle, "g_str_equal");
                IntPtr error2 = dlerror();
                if (error2 != IntPtr.Zero)
                {
                    string? errorMsg = Marshal.PtrToStringUTF8(error2);
                    dlclose(libHandle);
                    throw new InvalidOperationException($"Failed to find g_str_equal symbol: {errorMsg}");
                }

                if (gStrEqualPtr == IntPtr.Zero)
                {
                    dlclose(libHandle);
                    throw new InvalidOperationException("g_str_equal symbol pointer is null");
                }

                // Only set static fields after ALL operations succeed
                // Note: We intentionally keep libHandle open - see comment at top of method
                _gStrHashPtr = gStrHashPtr;
                _gStrEqualPtr = gStrEqualPtr;
            }
            catch
            {
                // On failure, close the library handle if we opened it
                if (libHandle != IntPtr.Zero)
                {
                    try
                    {
                        dlclose(libHandle);
                    }
                    catch
                    {
                        // Suppress dlclose exceptions during error handling
                    }
                }
                throw;
            }
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
        // Initialize function pointers if needed
        InitializeGLibFunctionPointers();

        // Create GHashTable for attributes
        IntPtr attributes = g_hash_table_new_full(
            _gStrHashPtr,
            _gStrEqualPtr,
            IntPtr.Zero,  // key_destroy_func - NULL, we manage memory manually
            IntPtr.Zero); // value_destroy_func - NULL, we manage memory manually

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
                throw new OutOfMemoryException("Failed to allocate memory for 'service' key");

            serviceValue = g_strdup(service);
            if (serviceValue == IntPtr.Zero)
                throw new OutOfMemoryException($"Failed to allocate memory for service value '{service}'");

            g_hash_table_insert(attributes, serviceKey, serviceValue);

            // Allocate and insert account attribute
            accountKey = g_strdup("account");
            if (accountKey == IntPtr.Zero)
                throw new OutOfMemoryException("Failed to allocate memory for 'account' key");

            accountValue = g_strdup(account);
            if (accountValue == IntPtr.Zero)
                throw new OutOfMemoryException($"Failed to allocate memory for account value '{account}'");

            g_hash_table_insert(attributes, accountKey, accountValue);

            IntPtr error = IntPtr.Zero;

            // Lookup password using the attribute hash table
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

            // No password found (not an error, just no matching entry)
            if (passwordPtr == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                // Marshal UTF-8 string from native memory
                string? result = Marshal.PtrToStringUTF8(passwordPtr);
                return result;
            }
            finally
            {
                // Always free the password memory
                secret_password_free(passwordPtr);
            }
        }
        finally
        {
            // Clean up all allocated resources
            // Wrap each cleanup in try-catch to ensure we attempt all cleanups
            // even if one fails, and to avoid masking the original exception
            
            try
            {
                // Destroy the hash table first (removes references, doesn't free strings)
                if (attributes != IntPtr.Zero)
                    g_hash_table_destroy(attributes);
            }
            catch
            {
                // Suppress hash table cleanup exceptions
            }

            // Now free the strings we allocated with g_strdup
            try
            {
                if (serviceKey != IntPtr.Zero)
                    g_free(serviceKey);
            }
            catch
            {
                // Suppress g_free exceptions
            }

            try
            {
                if (serviceValue != IntPtr.Zero)
                    g_free(serviceValue);
            }
            catch
            {
                // Suppress g_free exceptions
            }

            try
            {
                if (accountKey != IntPtr.Zero)
                    g_free(accountKey);
            }
            catch
            {
                // Suppress g_free exceptions
            }

            try
            {
                if (accountValue != IntPtr.Zero)
                    g_free(accountValue);
            }
            catch
            {
                // Suppress g_free exceptions
            }
        }
    }

    /// <summary>
    /// Extracts error message from GError structure using proper marshaling.
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

    #region P/Invoke Declarations

    private const int RTLD_LAZY = 0x00001;

    /// <summary>
    /// Open a shared library.
    /// </summary>
    [DllImport("libdl.so.2", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr dlopen([MarshalAs(UnmanagedType.LPUTF8Str)] string filename, int flags);

    /// <summary>
    /// Close a shared library.
    /// </summary>
    [DllImport("libdl.so.2", CallingConvention = CallingConvention.Cdecl)]
    private static extern int dlclose(IntPtr handle);

    /// <summary>
    /// Get the address of a symbol in a shared library.
    /// </summary>
    [DllImport("libdl.so.2", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr dlsym(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string symbol);

    /// <summary>
    /// Get the last error from dynamic linker.
    /// </summary>
    [DllImport("libdl.so.2", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr dlerror();

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

    #endregion
}
