using System;
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
        string hostname = configuration[nameof(Hostname)] ?? "";
        int httpsPort = configuration.GetValue<int>(nameof(HttpsPort), 443);
        int httpPort = configuration.GetValue<int>(nameof(HttpPort), 80);
        string certificatePath = configuration[nameof(CertificatePath)] ?? "";
        string certificatePassword = configuration[nameof(CertificatePassword)] ?? "";

        if (string.IsNullOrWhiteSpace(hostname))
        {
            throw new ArgumentException(nameof(Hostname) + " must be configured and cannot be empty.", nameof(Hostname));
        }

        if ((httpsPort < 1) || (httpsPort > ushort.MaxValue))
        {
            throw new ArgumentOutOfRangeException(nameof(HttpsPort), httpsPort, nameof(HttpsPort) + " must be between 1 and " + ushort.MaxValue + ".");
        }

        if ((httpPort < 1) || (httpPort > ushort.MaxValue))
        {
            throw new ArgumentOutOfRangeException(nameof(HttpPort), httpPort, nameof(HttpPort) + " must be between 1 and " + ushort.MaxValue + ".");
        }

        if (httpPort == httpsPort)
        {
            throw new ArgumentException(nameof(HttpPort) + " and " + nameof(HttpsPort) + " must be different. Both are set to " + httpPort + ".");
        }

        if (string.IsNullOrWhiteSpace(certificatePath))
        {
            throw new ArgumentException(nameof(CertificatePath) + " must be configured and cannot be empty.", nameof(CertificatePath));
        }

        if (string.IsNullOrWhiteSpace(certificatePassword))
        {
            throw new ArgumentException(nameof(CertificatePassword) + " must be configured and cannot be empty.", nameof(CertificatePassword));
        }

        Hostname = hostname;
        HttpsPort = httpsPort;
        HttpPort = httpPort;
        CertificatePath = certificatePath;
        CertificatePassword = certificatePassword;
    }
}
