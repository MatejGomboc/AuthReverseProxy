using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace AuthReverseProxy;

/// <summary>
/// Application configuration with automatic validation.
/// </summary>
public sealed record ApplicationConfiguration : IValidatableObject
{
    /// <summary>
    /// Gets the hostname/IP address the server listens on.
    /// </summary>
    public required System.Net.IPAddress Hostname { get; init; }

    /// <summary>
    /// Gets the HTTPS port number (must be different from HTTP port).
    /// </summary>
    [Range(1, 65535, ErrorMessage = "HTTPS port must be between 1 and 65535.")]
    public required ushort HttpsPort { get; init; }

    /// <summary>
    /// Gets the HTTP port number (must be different from HTTPS port).
    /// </summary>
    [Range(1, 65535, ErrorMessage = "HTTP port must be between 1 and 65535.")]
    public required ushort HttpPort { get; init; }

    /// <summary>
    /// Gets the path to the HTTPS certificate file.
    /// </summary>
    [Required(ErrorMessage = "HTTPS certificate path is required.")]
    [MinLength(1, ErrorMessage = "HTTPS certificate path cannot be empty.")]
    public required string HttpsCertificatePath { get; init; }

    /// <summary>
    /// Gets the password for the HTTPS certificate.
    /// </summary>
    public required string HttpsCertificatePassword { get; init; }

    /// <summary>
    /// Validates the configuration, checking cross-property constraints.
    /// </summary>
    /// <param name="validationContext">The validation context.</param>
    /// <returns>A collection of validation results.</returns>
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        // Validate that HTTP and HTTPS ports are different
        if (HttpPort == HttpsPort)
        {
            yield return new ValidationResult(
                $"HTTP port and HTTPS port must be different. Both are set to {HttpPort}.",
                new[] { nameof(HttpPort), nameof(HttpsPort) });
        }

        // Additional validation for certificate path (redundant with [MinLength] but more specific)
        if (string.IsNullOrWhiteSpace(HttpsCertificatePath))
        {
            yield return new ValidationResult(
                "HTTPS certificate path cannot be empty or whitespace.",
                new[] { nameof(HttpsCertificatePath) });
        }
    }
}
