using System;
using System.IO;
using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

public sealed class ApplicationConfiguration
{
    public string Hostname { get; }
    public int HttpsPort { get; }
    public int HttpPort { get; }
    public string CertificatePath { get; }
    public string CertificatePassword { get; }

    public ApplicationConfiguration(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        // Read configuration values without defaults - null means missing configuration
        string? hostname = configuration[nameof(Hostname)];
        string? httpsPortString = configuration[nameof(HttpsPort)];
        string? httpPortString = configuration[nameof(HttpPort)];
        string? certificatePath = configuration[nameof(CertificatePath)];
        string? certificatePassword = configuration[nameof(CertificatePassword)];

        // Validate Hostname
        if (hostname is null)
        {
            throw new ArgumentNullException(nameof(Hostname), $"{nameof(Hostname)} is missing from configuration.");
        }

        hostname = hostname.Trim();

        if (hostname.Length == 0)
        {
            throw new ArgumentException($"{nameof(Hostname)} cannot be empty.", nameof(Hostname));
        }

        // Validate HttpsPort
        if (httpsPortString is null)
        {
            throw new ArgumentNullException(nameof(HttpsPort), $"{nameof(HttpsPort)} is missing from configuration.");
        }

        if (!int.TryParse(httpsPortString, out int httpsPort))
        {
            throw new ArgumentException($"{nameof(HttpsPort)} must be a valid integer. Got: '{httpsPortString}'", nameof(HttpsPort));
        }

        if (httpsPort < 1 || httpsPort > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(HttpsPort), httpsPort, $"{nameof(HttpsPort)} must be between 1 and {ushort.MaxValue}.");
        }

        // Validate HttpPort
        if (httpPortString is null)
        {
            throw new ArgumentNullException(nameof(HttpPort), $"{nameof(HttpPort)} is missing from configuration.");
        }

        if (!int.TryParse(httpPortString, out int httpPort))
        {
            throw new ArgumentException($"{nameof(HttpPort)} must be a valid integer. Got: '{httpPortString}'", nameof(HttpPort));
        }

        if (httpPort < 1 || httpPort > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(HttpPort), httpPort, $"{nameof(HttpPort)} must be between 1 and {ushort.MaxValue}.");
        }

        // Validate ports are different
        if (httpPort == httpsPort)
        {
            throw new ArgumentException($"{nameof(HttpPort)} and {nameof(HttpsPort)} must be different. Both are set to {httpPort}.");
        }

        // Validate CertificatePath
        if (certificatePath is null)
        {
            throw new ArgumentNullException(nameof(CertificatePath), $"{nameof(CertificatePath)} is missing from configuration.");
        }

        certificatePath = certificatePath.Trim();

        if (certificatePath.Length == 0)
        {
            throw new ArgumentException($"{nameof(CertificatePath)} cannot be empty.", nameof(CertificatePath));
        }

        // Normalize path - resolves "..", makes absolute, standardizes separators
        certificatePath = Path.GetFullPath(certificatePath);

        // Validate CertificatePassword
        if (certificatePassword is null)
        {
            throw new ArgumentNullException(nameof(CertificatePassword), $"{nameof(CertificatePassword)} is missing from configuration.");
        }

        certificatePassword = certificatePassword.Trim();

        if (certificatePassword.Length == 0)
        {
            throw new ArgumentException($"{nameof(CertificatePassword)} cannot be empty.", nameof(CertificatePassword));
        }

        // All validation passed - assign to properties
        Hostname = hostname;
        HttpsPort = httpsPort;
        HttpPort = httpPort;
        CertificatePath = certificatePath;
        CertificatePassword = certificatePassword;
    }
}
