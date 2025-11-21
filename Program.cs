using System;
using System.Net;
using AuthReverseProxy;
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

builder.Configuration.Sources.Clear();

builder.Configuration.AddJsonFile("config.json", optional: false, reloadOnChange: false);

builder.Configuration.AddJsonFile("config.local.json", optional: true, reloadOnChange: false);

ApplicationConfiguration? config = builder.Configuration.Get<ApplicationConfiguration>();

if (config is null)
{
    Console.Error.WriteLine("Configuration error: Failed to load configuration.");
    return 1;
}

try
{
    config.Validate();
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"Configuration error: {ex.Message}");
    return 1;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Unexpected error validating configuration: {ex.Message}");
    return 1;
}

builder.Services.Configure<HttpsRedirectionOptions>(options =>
{
    options.HttpsPort = config.HttpsPort;
});

builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Parse(config.Hostname), config.HttpsPort, listenOptions =>
    {
        listenOptions.UseHttps(config.CertificatePath, config.CertificatePassword);
    });

    options.Listen(IPAddress.Parse(config.Hostname), config.HttpPort);
});

WebApplication app = builder.Build();

app.UseHttpsRedirection();

app.MapGet("/", () => "Hello World!");

app.Run();

return 0;
