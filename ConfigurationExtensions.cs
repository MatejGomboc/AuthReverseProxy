using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using Microsoft.Extensions.Configuration;

namespace AuthReverseProxy;

/// <summary>
/// Extension methods for IConfiguration.
/// </summary>
public static class ConfigurationExtensions
{
    /// <summary>
    /// Gets and validates a strongly-typed configuration object.
    /// Validates both data annotations and IValidatableObject if implemented.
    /// </summary>
    /// <typeparam name="T">The type of configuration object to bind and validate.</typeparam>
    /// <param name="configuration">The configuration instance.</param>
    /// <returns>A validated configuration object of type T.</returns>
    /// <exception cref="InvalidOperationException">Thrown when configuration is null or validation fails.</exception>
    public static T GetValidated<T>(this IConfiguration configuration) where T : class
    {
        T config = configuration.Get<T>()
            ?? throw new InvalidOperationException($"Configuration of type {typeof(T).Name} is null.");

        List<ValidationResult> validationResults = [];
        ValidationContext validationContext = new(config);

        if (!Validator.TryValidateObject(config, validationContext, validationResults, validateAllProperties: true))
        {
            string errors = string.Join(Environment.NewLine, validationResults.Select(r => r.ErrorMessage));
            throw new InvalidOperationException($"Configuration validation failed:{Environment.NewLine}{errors}");
        }

        return config;
    }
}
