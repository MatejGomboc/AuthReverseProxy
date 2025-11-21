using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Clear default configuration sources
builder.Configuration.Sources.Clear();

// Add custom config.json
builder.Configuration.AddJsonFile("config.json", optional: false, reloadOnChange: true);

// Set environment based on compile-time constant
#if DEVELOPMENT
builder.Environment.EnvironmentName = Environments.Development;
#else
builder.Environment.EnvironmentName = Environments.Production;
#endif

// Configure Kestrel with HTTPS only
string hostname = builder.Configuration["Hostname"] ?? "localhost";
int httpsPort = builder.Configuration.GetValue<int>("HttpsPort", 7000);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(httpsPort, listenOptions =>
    {
        listenOptions.UseHttps();
    });
});

WebApplication app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.Run();
