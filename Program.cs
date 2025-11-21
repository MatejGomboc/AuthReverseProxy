using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    ApplicationName = "AuthReverseProxy",
    Args = [],
    ContentRootPath = AppContext.BaseDirectory,
    WebRootPath = "",
    EnvironmentName = 
#if DEVELOPMENT
        Environments.Development
#else
        Environments.Production
#endif
});

// Clear default configuration sources
builder.Configuration.Sources.Clear();

// Add custom config.json (required)
builder.Configuration.AddJsonFile("config.json", optional: false, reloadOnChange: false);

// Add optional config.local.json for local development overrides (not committed)
builder.Configuration.AddJsonFile("config.local.json", optional: true, reloadOnChange: false);

// Read and validate configuration
string hostname = builder.Configuration["Hostname"] ?? "localhost";
int httpsPort = builder.Configuration.GetValue<int>("HttpsPort", 443);
int httpPort = builder.Configuration.GetValue<int>("HttpPort", 80);
string certificatePath = builder.Configuration["CertificatePath"] ?? "";
string certificatePassword = builder.Configuration["CertificatePassword"] ?? "";

// Validate configuration
if (string.IsNullOrWhiteSpace(hostname))
{
    throw new InvalidOperationException("Hostname must be configured.");
}

if (httpsPort < 1 || httpsPort > 65535)
{
    throw new InvalidOperationException($"Invalid HttpsPort: {httpsPort}. Must be between 1 and 65535.");
}

if (httpPort < 1 || httpPort > 65535)
{
    throw new InvalidOperationException($"Invalid HttpPort: {httpPort}. Must be between 1 and 65535.");
}

if (httpPort == httpsPort)
{
    throw new InvalidOperationException("HttpPort and HttpsPort must be different.");
}

bool useDevelopmentCertificate = string.IsNullOrWhiteSpace(certificatePath);

if (!useDevelopmentCertificate && !File.Exists(certificatePath))
{
    throw new InvalidOperationException($"Certificate file not found: {certificatePath}");
}

// Configure HTTPS redirection
builder.Services.Configure<HttpsRedirectionOptions>(options =>
{
    options.HttpsPort = httpsPort;
});

// Configure Kestrel
builder.WebHost.ConfigureKestrel(options =>
{
    // HTTPS endpoint
    options.Listen(IPAddress.Parse(hostname), httpsPort, listenOptions =>
    {
        if (useDevelopmentCertificate)
        {
            listenOptions.UseHttps();
        }
        else
        {
            listenOptions.UseHttps(certificatePath, certificatePassword);
        }
    });

    // HTTP endpoint (for redirect)
    options.Listen(IPAddress.Parse(hostname), httpPort);
});

WebApplication app = builder.Build();

// Redirect HTTP to HTTPS
app.UseHttpsRedirection();

app.MapGet("/", () => "Hello World!");

app.Run();
