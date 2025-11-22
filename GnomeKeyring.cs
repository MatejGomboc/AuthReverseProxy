using System;
using System.Runtime.InteropServices;

namespace AuthReverseProxy;

/// <summary>
/// Provides access to GNOME Keyring secrets via libsecret.
/// Handles all native interop with libsecret and GLib libraries.
/// </summary>
public static class GnomeKeyring
{
    private const string LibSecret = "libsecret-1.so.0";
    private const string LibGLib = "libglib-2.0.so.0";

    private const string ServiceAttribute = "service";
    private const string AccountAttribute = "account";

    // Keep library handle to prevent premature unloading by GC.
    private static readonly IntPtr _libGLibHandle;

    // Cache native function pointers as static fields.
    // These are loaded once and reused, avoiding overhead on every call.
    private static readonly IntPtr _gStrHashFuncPtr;
    private static readonly IntPtr _gStrEqualFuncPtr;
    private static readonly IntPtr _gFreeFuncPtr;

    /// <summary>
    /// Static constructor to initialize cached function pointers from native libraries.
    /// </summary>
    static GnomeKeyring()
    {
        try
        {
            // Load GLib library and retain handle to prevent premature unloading by GC.
            _libGLibHandle = NativeLibrary.Load(LibGLib);

            _gStrHashFuncPtr = NativeLibrary.GetExport(_libGLibHandle, "g_str_hash");
            _gStrEqualFuncPtr = NativeLibrary.GetExport(_libGLibHandle, "g_str_equal");
            _gFreeFuncPtr = NativeLibrary.GetExport(_libGLibHandle, "g_free");

            if ((_gStrHashFuncPtr == IntPtr.Zero) || (_gStrEqualFuncPtr == IntPtr.Zero) || (_gFreeFuncPtr == IntPtr.Zero))
            {
                throw new InvalidOperationException("Failed to load required GLib function pointers.");
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to initialize GnomeKeyring: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Retrieves a secret from GNOME Keyring using the specified service and account identifiers.
    /// </summary>
    /// <param name="service">The service name for keyring lookup.</param>
    /// <param name="account">The account name for keyring lookup.</param>
    /// <returns>The retrieved secret, or null if not found.</returns>
    /// <remarks>
    /// This method uses a synchronous blocking call to the keyring daemon. The call will block until the keyring daemon responds, which is typically
    /// very fast (microseconds to low milliseconds) if the keyring is unlocked. If the keyring is locked, the system may prompt for the keyring password,
    /// which requires user interaction. In automated scenarios, ensure the keyring is unlocked before application startup.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when service or account is null.</exception>
    /// <exception cref="ArgumentException">Thrown when service or account is empty or whitespace.</exception>
    /// <exception cref="InvalidOperationException">Thrown when keyring lookup fails.</exception>
    public static string? GetSecret(string service, string account)
    {
        if (service is null)
        {
            throw new ArgumentNullException(nameof(service));
        }

        if (account is null)
        {
            throw new ArgumentNullException(nameof(account));
        }

        if (string.IsNullOrWhiteSpace(service))
        {
            throw new ArgumentException("Service name cannot be empty or whitespace.", nameof(service));
        }

        if (string.IsNullOrWhiteSpace(account))
        {
            throw new ArgumentException("Account name cannot be empty or whitespace.", nameof(account));
        }

        try
        {
            return FetchSecretFromKeyring(service, account);
        }
        catch (DllNotFoundException ex)
        {
            string message = $"Required library not found: {ex.Message}. Ensure libsecret-1 and libglib-2.0 are installed.";
            throw new InvalidOperationException(message, ex);
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
        // Create GHashTable for attributes with g_free as destroy functions.
        // This way the hash table will automatically free keys and values when destroyed.
        IntPtr attributes = g_hash_table_new_full(
            _gStrHashFuncPtr,  // Direct pointer to g_str_hash.
            _gStrEqualFuncPtr, // Direct pointer to g_str_equal.
            _gFreeFuncPtr,     // g_free for keys - hash table owns the memory.
            _gFreeFuncPtr      // g_free for values - hash table owns the memory.
        );

        if (attributes == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to create GHashTable for attributes.");
        }

        try
        {
            // Allocate and insert service attribute.
            IntPtr serviceKey = g_strdup(ServiceAttribute);
            if (serviceKey == IntPtr.Zero)
            {
                throw new OutOfMemoryException($"Failed to allocate memory for '{ServiceAttribute}' key.");
            }

            IntPtr serviceValue = g_strdup(service);
            if (serviceValue == IntPtr.Zero)
            {
                g_free(serviceKey); // Clean up the key we just allocated.
                throw new OutOfMemoryException($"Failed to allocate memory for service value '{service}'.");
            }

            // Hash table takes ownership of key and value.
            g_hash_table_insert(attributes, serviceKey, serviceValue);

            // Allocate and insert account attribute.
            IntPtr accountKey = g_strdup(AccountAttribute);
            if (accountKey == IntPtr.Zero)
            {
                throw new OutOfMemoryException($"Failed to allocate memory for '{AccountAttribute}' key.");
            }

            IntPtr accountValue = g_strdup(account);
            if (accountValue == IntPtr.Zero)
            {
                g_free(accountKey); // Clean up the key we just allocated.
                throw new OutOfMemoryException($"Failed to allocate memory for account value '{account}'.");
            }

            // Hash table takes ownership of key and value.
            g_hash_table_insert(attributes, accountKey, accountValue);

            // Lookup password using the attribute hash table.
            // Note: This is a synchronous blocking call. It will wait for the keyring daemon to respond. Cancellable is set to NULL (IntPtr.Zero), meaning
            // this operation cannot be cancelled once started.
            IntPtr passwordPtr = secret_password_lookupv_sync(
                IntPtr.Zero,     // schema (NULL = generic schema)
                attributes,      // attribute hash table
                IntPtr.Zero,     // cancellable (NULL = no cancellation support)
                out IntPtr error // error output
            );

            // Check for errors first - per libsecret docs, if error is set, passwordPtr should be NULL.
            if (error != IntPtr.Zero)
            {
                string? errorMessage = GetGErrorMessage(error);
                g_error_free(error);
                throw new InvalidOperationException($"libsecret error: {errorMessage ?? "Unknown error"}");
            }

            // No password found (not an error, just no matching entry).
            if (passwordPtr == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                // Marshal UTF-8 string from native memory.
                string? password = Marshal.PtrToStringUTF8(passwordPtr);

                if (password is null)
                {
                    throw new InvalidOperationException("Failed to marshal password from native memory - PtrToStringUTF8 returned null.");
                }

                return password;
            }
            finally
            {
                // Always free the password memory.
                secret_password_free(passwordPtr);
            }
        }
        finally
        {
            // Destroy hash table - this will automatically free all keys and values because we passed g_free as the destroy functions.
            if (attributes != IntPtr.Zero)
            {
                try
                {
                    g_hash_table_destroy(attributes);
                }
                catch (Exception cleanupEx)
                {
                    // Log cleanup exceptions to aid debugging, but don't mask primary exception.
                    Console.Error.WriteLine($"Warning: Exception during hash table cleanup: {cleanupEx.Message}");
                }
            }
        }
    }

    /// <summary>
    /// Extracts error message from GError structure.
    /// </summary>
    private static string? GetGErrorMessage(IntPtr error)
    {
        if (error == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            // Use Marshal.PtrToStructure for safe, portable access.
            GErrorStruct gError = Marshal.PtrToStructure<GErrorStruct>(error);

            if (gError.message == IntPtr.Zero)
            {
                return null;
            }

            return Marshal.PtrToStringUTF8(gError.message);
        }
        catch
        {
            return null;
        }
    }

    #region Structures

    /// <summary>
    /// GError structure definition with proper layout.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct GErrorStruct
    {
        public uint domain; // GQuark (guint32)
        public int code; // gint (gint32)
        public IntPtr message; // gchar* - marshaler handles padding correctly
    }

    #endregion

    #region P/Invoke Declarations

    /// <summary>
    /// Lookup a password using attributes hash table.
    /// This is a synchronous blocking call that waits for the keyring daemon to respond.
    /// </summary>
    [DllImport(LibSecret, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr secret_password_lookupv_sync(IntPtr schema, IntPtr attributes, IntPtr cancellable, out IntPtr error);

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
    private static extern IntPtr g_hash_table_new_full(IntPtr hash_func, IntPtr key_equal_func, IntPtr key_destroy_func, IntPtr value_destroy_func);

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
