using System.Net;
using AuthReverseProxy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
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

// Load and validate configuration
ApplicationConfiguration config;
try
{
    config = new ApplicationConfiguration(builder.Configuration);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"Configuration error: {ex.Message}");
    return 1;
}
catch (ArgumentOutOfRangeException ex)
{
    Console.Error.WriteLine($"Configuration error: {ex.Message}");
    return 1;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Unexpected error loading configuration: {ex.Message}");
    return 1;
}

// Configure HTTPS redirection
builder.Services.Configure<HttpsRedirectionOptions>(options =>
{
    options.HttpsPort = config.HttpsPort;
});

// Configure Kestrel
builder.WebHost.ConfigureKestrel(options =>
{
    // HTTPS endpoint
    options.Listen(IPAddress.Parse(config.Hostname), config.HttpsPort, listenOptions =>
    {
        if (string.IsNullOrWhiteSpace(config.CertificatePath))
        {
            listenOptions.UseHttps();
        }
        else
        {
            listenOptions.UseHttps(config.CertificatePath, config.CertificatePassword);
        }
    });

    // HTTP endpoint (for redirect)
    options.Listen(IPAddress.Parse(config.Hostname), config.HttpPort);
});

WebApplication app = builder.Build();

// Redirect HTTP to HTTPS
app.UseHttpsRedirection();

app.MapGet("/", () => "Hello World!");

app.Run();

return 0;
