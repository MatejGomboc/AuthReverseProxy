using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

/// <summary>
/// Represents the application's configuration with comprehensive validation.
/// </summary>
public sealed class ApplicationConfiguration
{
    private const int MinPort = 1;
    private const int MaxPort = 65535;
    private const int MinUnprivilegedPort = 1024;
    
    // RFC 1123 compliant hostname regex (simplified)
    private static readonly Regex HostnameRegex = new(
        @"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.?)+$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(1));

    /// <summary>
    /// Gets the hostname for the reverse proxy.
    /// </summary>
    public string Hostname { get; }
    
    /// <summary>
    /// Gets the HTTPS port number.
    /// </summary>
    public int HttpsPort { get; }
    
    /// <summary>
    /// Gets the HTTP port number.
    /// </summary>
    public int HttpPort { get; }
    
    /// <summary>
    /// Gets the path to the SSL/TLS certificate file.
    /// </summary>
    public string CertificatePath { get; }
    
    /// <summary>
    /// Gets the password for the SSL/TLS certificate.
    /// </summary>
    public string CertificatePassword { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApplicationConfiguration"/> class.
    /// </summary>
    /// <param name="configuration">The configuration source.</param>
    /// <exception cref="ArgumentNullException">Thrown when configuration is null.</exception>
    /// <exception cref="ArgumentException">Thrown when configuration values are invalid.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when port numbers are out of valid range.</exception>
    /// <exception cref="FileNotFoundException">Thrown when certificate file is not found.</exception>
    /// <exception cref="InvalidOperationException">Thrown when certificate is invalid or cannot be loaded.</exception>
    public ApplicationConfiguration(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration, nameof(configuration));

        // Read configuration values
        string hostname = configuration[nameof(Hostname)] ?? string.Empty;
        int httpsPort = configuration.GetValue<int>(nameof(HttpsPort), 443);
        int httpPort = configuration.GetValue<int>(nameof(HttpPort), 80);
        string certificatePath = configuration[nameof(CertificatePath)] ?? string.Empty;
        string certificatePassword = configuration[nameof(CertificatePassword)] ?? string.Empty;

        // Validate hostname
        ValidateHostname(hostname);

        // Validate ports
        ValidatePort(httpsPort, nameof(HttpsPort));
        ValidatePort(httpPort, nameof(HttpPort));
        ValidatePortsAreDifferent(httpPort, httpsPort);

        // Validate certificate configuration
        ValidateCertificatePath(certificatePath);
        ValidateCertificatePassword(certificatePassword);
        ValidateCertificateFile(certificatePath, certificatePassword);

        // Assign validated values
        Hostname = hostname.Trim();
        HttpsPort = httpsPort;
        HttpPort = httpPort;
        CertificatePath = certificatePath.Trim();
        CertificatePassword = certificatePassword;
    }

    /// <summary>
    /// Validates that the hostname is in a valid format.
    /// </summary>
    private static void ValidateHostname(string hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname))
        {
            throw new ArgumentException(
                $"{nameof(Hostname)} must be configured and cannot be empty.",
                nameof(Hostname));
        }

        string trimmedHostname = hostname.Trim();

        // Check if it's a valid IP address
        if (IPAddress.TryParse(trimmedHostname, out _))
        {
            return; // Valid IP address
        }

        // Check if it's a valid hostname using RFC 1123 rules
        if (!HostnameRegex.IsMatch(trimmedHostname))
        {
            throw new ArgumentException(
                $"{nameof(Hostname)} '{trimmedHostname}' is not a valid hostname or IP address. " +
                "It must be a valid DNS hostname (RFC 1123) or IP address.",
                nameof(Hostname));
        }

        // Additional checks for hostname length
        if (trimmedHostname.Length > 253)
        {
            throw new ArgumentException(
                $"{nameof(Hostname)} '{trimmedHostname}' exceeds the maximum length of 253 characters.",
                nameof(Hostname));
        }

        // Check for localhost variations (security warning)
        if (trimmedHostname.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            trimmedHostname.StartsWith("127.", StringComparison.Ordinal) ||
            trimmedHostname.Equals("::1", StringComparison.Ordinal))
        {
            Console.WriteLine(
                $"Warning: {nameof(Hostname)} is set to '{trimmedHostname}' which is only accessible locally. " +
                "This may not be suitable for production deployments.");
        }
    }

    /// <summary>
    /// Validates that the port number is within the valid range.
    /// </summary>
    private static void ValidatePort(int port, string portName)
    {
        if (port is < MinPort or > MaxPort)
        {
            throw new ArgumentOutOfRangeException(
                portName,
                port,
                $"{portName} must be between {MinPort} and {MaxPort}.");
        }

        // Warning for privileged ports on Unix-like systems
        if (port < MinUnprivilegedPort && !OperatingSystem.IsWindows())
        {
            Console.WriteLine(
                $"Warning: {portName} is set to {port}, which is a privileged port on Unix-like systems. " +
                "The application must run with appropriate permissions or use port forwarding.");
        }

        // Warning for well-known reserved ports
        if (port == 22 || port == 25 || port == 53)
        {
            Console.WriteLine(
                $"Warning: {portName} is set to {port}, which is typically reserved for other services " +
                "(SSH, SMTP, DNS). This may cause conflicts.");
        }
    }

    /// <summary>
    /// Validates that HTTP and HTTPS ports are different.
    /// </summary>
    private static void ValidatePortsAreDifferent(int httpPort, int httpsPort)
    {
        if (httpPort == httpsPort)
        {
            throw new ArgumentException(
                $"{nameof(HttpPort)} and {nameof(HttpsPort)} must be different. Both are set to {httpPort}.");
        }
    }

    /// <summary>
    /// Validates that the certificate path is not empty and the file exists.
    /// </summary>
    private static void ValidateCertificatePath(string certificatePath)
    {
        if (string.IsNullOrWhiteSpace(certificatePath))
        {
            throw new ArgumentException(
                $"{nameof(CertificatePath)} must be configured and cannot be empty.",
                nameof(CertificatePath));
        }

        string trimmedPath = certificatePath.Trim();

        // Check if the path contains invalid characters
        if (trimmedPath.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
        {
            throw new ArgumentException(
                $"{nameof(CertificatePath)} '{trimmedPath}' contains invalid path characters.",
                nameof(CertificatePath));
        }

        // Check if file exists
        if (!File.Exists(trimmedPath))
        {
            throw new FileNotFoundException(
                $"Certificate file not found at path '{trimmedPath}'. " +
                "Please ensure the certificate file exists and the path is correct.",
                trimmedPath);
        }

        // Check file extension
        string extension = Path.GetExtension(trimmedPath).ToLowerInvariant();
        if (extension is not (".pfx" or ".p12" or ".pem" or ".crt" or ".cer"))
        {
            Console.WriteLine(
                $"Warning: Certificate file '{trimmedPath}' has extension '{extension}'. " +
                "Expected extensions are .pfx, .p12, .pem, .crt, or .cer. " +
                "Ensure the file format is correct.");
        }
    }

    /// <summary>
    /// Validates that the certificate password is not empty.
    /// </summary>
    private static void ValidateCertificatePassword(string certificatePassword)
    {
        if (string.IsNullOrWhiteSpace(certificatePassword))
        {
            throw new ArgumentException(
                $"{nameof(CertificatePassword)} must be configured and cannot be empty. " +
                "If the certificate is not password-protected, use an empty configuration value explicitly.",
                nameof(CertificatePassword));
        }

        // Security recommendation for password length
        if (certificatePassword.Length < 8)
        {
            Console.WriteLine(
                $"Warning: {nameof(CertificatePassword)} is shorter than 8 characters. " +
                "For production environments, use a strong password of at least 12 characters.");
        }
    }

    /// <summary>
    /// Validates that the certificate file can be loaded and is valid.
    /// </summary>
    private static void ValidateCertificateFile(string certificatePath, string certificatePassword)
    {
        X509Certificate2? certificate = null;
        try
        {
            // Attempt to load the certificate to validate it
            certificate = new X509Certificate2(certificatePath, certificatePassword);

            // Check if certificate has a private key
            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException(
                    $"Certificate at '{certificatePath}' does not contain a private key. " +
                    "SSL/TLS certificates for servers must include a private key.");
            }

            // Check certificate validity period
            DateTime now = DateTime.Now;
            if (now < certificate.NotBefore)
            {
                throw new InvalidOperationException(
                    $"Certificate at '{certificatePath}' is not yet valid. " +
                    $"Valid from: {certificate.NotBefore:yyyy-MM-dd HH:mm:ss}");
            }

            if (now > certificate.NotAfter)
            {
                throw new InvalidOperationException(
                    $"Certificate at '{certificatePath}' has expired. " +
                    $"Expired on: {certificate.NotAfter:yyyy-MM-dd HH:mm:ss}");
            }

            // Warning if certificate expires soon (within 30 days)
            TimeSpan timeUntilExpiry = certificate.NotAfter - now;
            if (timeUntilExpiry.TotalDays < 30)
            {
                Console.WriteLine(
                    $"Warning: Certificate at '{certificatePath}' will expire in {timeUntilExpiry.TotalDays:F0} days " +
                    $"on {certificate.NotAfter:yyyy-MM-dd HH:mm:ss}. Please renew it soon.");
            }

            // Check if certificate is self-signed (informational)
            if (certificate.Subject == certificate.Issuer)
            {
                Console.WriteLine(
                    $"Information: Certificate at '{certificatePath}' appears to be self-signed. " +
                    "This is acceptable for development but not recommended for production.");
            }

            // Validate key usage for server authentication
            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension is X509EnhancedKeyUsageExtension ekuExtension)
                {
                    bool hasServerAuth = false;
                    foreach (var oid in ekuExtension.EnhancedKeyUsages)
                    {
                        if (oid.Value == "1.3.6.1.5.5.7.3.1") // Server Authentication OID
                        {
                            hasServerAuth = true;
                            break;
                        }
                    }

                    if (!hasServerAuth)
                    {
                        Console.WriteLine(
                            $"Warning: Certificate at '{certificatePath}' may not be configured for server authentication. " +
                            "This may cause SSL/TLS handshake failures.");
                    }
                }
            }
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            throw new InvalidOperationException(
                $"Failed to load certificate from '{certificatePath}'. " +
                "The file may be corrupted, the password may be incorrect, or the file format may be unsupported. " +
                $"Error: {ex.Message}",
                ex);
        }
        finally
        {
            certificate?.Dispose();
        }
    }
}
