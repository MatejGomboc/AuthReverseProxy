using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
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

// Get and validate configuration early
ApplicationConfiguration config = builder.Configuration.Get<ApplicationConfiguration>()
    ?? throw new InvalidOperationException("Configuration is null.");

// Manually validate the configuration using the validation attributes and IValidatableObject
List<ValidationResult> validationResults = new();
ValidationContext validationContext = new(config);
if (!Validator.TryValidateObject(config, validationContext, validationResults, validateAllProperties: true))
{
    string errors = string.Join(Environment.NewLine, validationResults.Select(r => r.ErrorMessage));
    throw new InvalidOperationException($"Configuration validation failed:{Environment.NewLine}{errors}");
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
