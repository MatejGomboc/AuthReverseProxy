using System;
using AuthReverseProxy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    ApplicationName = nameof(AuthReverseProxy),
    Args = [],
    ContentRootPath = AppContext.BaseDirectory,
    WebRootPath = "",
    EnvironmentName = ""
});

builder.Configuration.Sources.Clear();
builder.Configuration.AddJsonFile("config.json", optional: false, reloadOnChange: false);
builder.Configuration.AddJsonFile("config.local.json", optional: true, reloadOnChange: false);

builder.Configuration.Sources.Add(new KeyringConfigurationSource
{
    Service = nameof(AuthReverseProxy),
    Account = "HttpsCertificate",
    ConfigKey = nameof(ApplicationConfiguration.HttpsCertificatePassword)
});

// Configure options with automatic validation
builder.Services.AddOptions<ApplicationConfiguration>()
    .Bind(builder.Configuration)
    .ValidateDataAnnotations()
    .ValidateOnStart();

// Build a temporary service provider to get and validate configuration early
using ServiceProvider tempServiceProvider = builder.Services.BuildServiceProvider();
ApplicationConfiguration config = tempServiceProvider.GetRequiredService<IOptions<ApplicationConfiguration>>().Value;

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

// Configure Kestrel with validated configuration
builder.WebHost.ConfigureKestrel((KestrelServerOptions options) =>
{
    // HTTPS listener
    options.Listen(config.Hostname, config.HttpsPort, (ListenOptions listenOptions) =>
    {
        listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
        listenOptions.UseHttps(config.HttpsCertificatePath, config.HttpsCertificatePassword);
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
