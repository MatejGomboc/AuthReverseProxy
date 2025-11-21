using System;
using System.Net;
using AuthReverseProxy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    ApplicationName = "AuthReverseProxy",
    Args = [],
    ContentRootPath = AppContext.BaseDirectory,
    WebRootPath = "",
    EnvironmentName = ""
});

builder.Configuration.Sources.Clear();
builder.Configuration.AddJsonFile("config.json", optional: false, reloadOnChange: false);
builder.Configuration.AddJsonFile("config.local.json", optional: true, reloadOnChange: false);

ApplicationConfiguration? config = builder.Configuration.Get<ApplicationConfiguration>();

if (config is null)
{
    Console.Error.WriteLine("Configuration error: Config is null.");
    return 1;
}

if (config.HttpPort == config.HttpsPort)
{
    Console.Error.WriteLine("Configuration error: HTTP port and HTTPS port have the same value.");
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
