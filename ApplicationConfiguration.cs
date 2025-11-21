namespace AuthReverseProxy;

public sealed class ApplicationConfiguration
{
    public string Hostname { get; set; } = string.Empty;
    public ushort HttpsPort { get; set; }
    public ushort HttpPort { get; set; }
    public string CertificatePath { get; set; } = string.Empty;
    public string CertificatePassword { get; set; } = string.Empty;
}
