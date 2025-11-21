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
            throw new InvalidOperationException("Hostname must be configured and cannot be empty.");
        }

        // Validate HTTPS port
        if (httpsPort < 1 || httpsPort > 65535)
        {
            throw new InvalidOperationException($"Invalid HttpsPort: {httpsPort}. Must be between 1 and 65535.");
        }

        // Validate HTTP port
        if (httpPort < 1 || httpPort > 65535)
        {
            throw new InvalidOperationException($"Invalid HttpPort: {httpPort}. Must be between 1 and 65535.");
        }

        // Validate ports are different
        if (httpPort == httpsPort)
        {
            throw new InvalidOperationException("HttpPort and HttpsPort must be different.");
        }

        // Validate certificate file exists if path is specified
        if (!string.IsNullOrWhiteSpace(certificatePath) && !File.Exists(certificatePath))
        {
            throw new InvalidOperationException($"Certificate file not found: {certificatePath}");
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
