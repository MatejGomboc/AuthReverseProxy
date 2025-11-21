using System;
using AuthReverseProxy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Server.Kestrel.Core;
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
builder.Configuration.AddKeyring(); // Add keyring configuration provider for sensitive credentials

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

builder.Services.Configure<HttpsRedirectionOptions>((HttpsRedirectionOptions options) =>
{
    options.HttpsPort = config.HttpsPort;
    options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
});

builder.Services.AddHsts((HstsOptions options) =>
{
    options.MaxAge = TimeSpan.MaxValue;
    options.IncludeSubDomains = false; // Each domain should opt-in individually.
    options.Preload = false; // Each domain should opt-in individually.
});

builder.WebHost.ConfigureKestrel((KestrelServerOptions options) =>
{
    // HTTPS listener
    options.Listen(config.Hostname, config.HttpsPort, (ListenOptions listenOptions) =>
    {
        listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
        listenOptions.UseHttps(config.CertificatePath, config.CertificatePassword);
    });

    // HTTP listener (for redirects only)
    options.Listen(config.Hostname, config.HttpPort, (ListenOptions listenOptions) =>
    {
        listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
    });
});

WebApplication app = builder.Build();

app.UseHttpsRedirection();

app.UseHsts();

app.MapGet("/", () => "Hello World!");

app.Run();

return 0;
