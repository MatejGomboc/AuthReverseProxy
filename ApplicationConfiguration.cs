namespace AuthReverseProxy;

public sealed class ApplicationConfiguration
{
    public required System.Net.IPAddress Hostname { get; set; }
    public required ushort HttpsPort { get; set; }
    public required ushort HttpPort { get; set; }
    public required string HttpsCertificatePath { get; set; }
    public required string HttpsCertificatePassword { get; set; }
}
