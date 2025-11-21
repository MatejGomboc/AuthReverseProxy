using System;

namespace AuthReverseProxy;

public sealed class ApplicationConfiguration
{
    public string Hostname { get; set; } = string.Empty;
    public ushort HttpsPort { get; set; }
    public ushort HttpPort { get; set; }
    public string CertificatePath { get; set; } = string.Empty;
    public string CertificatePassword { get; set; } = string.Empty;

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Hostname, nameof(Hostname));

        if (HttpPort == HttpsPort)
        {
            throw new ArgumentException(
                $"{nameof(HttpPort)} and {nameof(HttpsPort)} must be different. Both are set to {HttpPort}.",
                nameof(HttpPort));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(CertificatePath, nameof(CertificatePath));
        ArgumentException.ThrowIfNullOrWhiteSpace(CertificatePassword, nameof(CertificatePassword));
    }
}
