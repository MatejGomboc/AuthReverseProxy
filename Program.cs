using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Clear default configuration sources
builder.Configuration.Sources.Clear();

// Add custom config.json (required)
builder.Configuration.AddJsonFile("config.json", optional: false, reloadOnChange: false);

// Add optional config.local.json for local development overrides (not committed)
builder.Configuration.AddJsonFile("config.local.json", optional: true, reloadOnChange: false);

// Set environment based on compile-time constant
#if DEVELOPMENT
builder.Environment.EnvironmentName = Environments.Development;
#else
builder.Environment.EnvironmentName = Environments.Production;
#endif

// Configure Kestrel with HTTPS as primary, HTTP for redirect
string hostname = builder.Configuration["Hostname"] ?? "localhost";
int httpsPort = builder.Configuration.GetValue<int>("HttpsPort", 443);
int httpPort = builder.Configuration.GetValue<int>("HttpPort", 80);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(httpsPort, listenOptions =>
    {
        listenOptions.UseHttps();
    });
    options.ListenAnyIP(httpPort);
});

WebApplication app = builder.Build();

// Redirect HTTP to HTTPS
app.UseHttpsRedirection();

app.MapGet("/", () => "Hello World!");

app.Run();
