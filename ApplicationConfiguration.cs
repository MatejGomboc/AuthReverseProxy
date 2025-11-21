using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

public sealed class ApplicationConfiguration
{
    public string Hostname { get; init; } = null!;
    public int HttpsPort { get; init; }
    public int HttpPort { get; init; }
    public string CertificatePath { get; init; } = null!;
    public string CertificatePassword { get; init; } = null!;

    private ApplicationConfiguration() { }

    public static ApplicationConfiguration LoadAndValidate(IConfiguration configuration)
    {
        string hostname = configuration["Hostname"] ?? "localhost";
        int httpsPort = configuration.GetValue<int>("HttpsPort", 443);
        int httpPort = configuration.GetValue<int>("HttpPort", 80);
        string certificatePath = configuration["CertificatePath"] ?? "";
        string certificatePassword = configuration["CertificatePassword"] ?? "";

        // Validate hostname
        if (string.IsNullOrWhiteSpace(hostname))
        {
            throw new ArgumentException("Hostname must be configured and cannot be empty.", nameof(hostname));
        }

        // Validate HTTPS port
        if (httpsPort < 1 || httpsPort > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(httpsPort), httpsPort, $"HttpsPort must be between 1 and {ushort.MaxValue}.");
        }

        // Validate HTTP port
        if (httpPort < 1 || httpPort > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(httpPort), httpPort, $"HttpPort must be between 1 and {ushort.MaxValue}.");
        }

        // Validate ports are different
        if (httpPort == httpsPort)
        {
            throw new ArgumentException($"HttpPort and HttpsPort must be different. Both are set to {httpPort}.");
        }

        // Validate certificate configuration: both path and password must be provided together
        bool hasPath = !string.IsNullOrWhiteSpace(certificatePath);
        bool hasPassword = !string.IsNullOrWhiteSpace(certificatePassword);
        
        if (hasPath && !hasPassword)
        {
            throw new ArgumentException("CertificatePassword must be provided when CertificatePath is specified.", nameof(certificatePassword));
        }
        
        if (!hasPath && hasPassword)
        {
            throw new ArgumentException("CertificatePath must be provided when CertificatePassword is specified.", nameof(certificatePath));
        }

        return new ApplicationConfiguration
        {
            Hostname = hostname,
            HttpsPort = httpsPort,
            HttpPort = httpPort,
            CertificatePath = certificatePath,
            CertificatePassword = certificatePassword
        };
    }
}
