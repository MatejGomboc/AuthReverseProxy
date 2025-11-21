namespace AuthReverseProxy;

public sealed class ApplicationConfiguration
{
    public System.Net.IPAddress Hostname { get; set; } = System.Net.IPAddress.Loopback;
    public ushort HttpsPort { get; set; }
    public ushort HttpPort { get; set; }
    public string CertificatePath { get; set; } = string.Empty;
    public string CertificatePassword { get; set; } = string.Empty;
}
