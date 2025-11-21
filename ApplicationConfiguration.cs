namespace AuthReverseProxy;

public sealed class ApplicationConfiguration
{
    public System.Net.IPAddress Hostname { get; set; } = System.Net.IPAddress.Loopback;
    public ushort HttpsPort { get; set; }
    public ushort HttpPort { get; set; }
    public string HttpsCertificatePath { get; set; } = string.Empty;
    public string HttpsCertificatePassword { get; set; } = string.Empty;
}
