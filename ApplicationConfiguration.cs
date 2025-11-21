namespace AuthReverseProxy;

public sealed record ApplicationConfiguration
{
    public required System.Net.IPAddress Hostname { get; init; }
    public required ushort HttpsPort { get; init; }
    public required ushort HttpPort { get; init; }
    public required string HttpsCertificatePath { get; init; }
    public required string HttpsCertificatePassword { get; init; }
}
