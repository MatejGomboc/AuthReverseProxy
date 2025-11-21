# Keyring Configuration

This document explains how to use GNOME Keyring for secure credential storage in AuthReverseProxy.

## Overview

AuthReverseProxy uses a custom configuration provider to retrieve sensitive credentials (like certificate passwords) from GNOME Keyring instead of storing them in configuration files. This provides:

- **Encryption at rest**: Passwords are encrypted by the keyring daemon
- **No plaintext secrets**: Credentials never appear in version control or config files
- **Standard Linux credential storage**: Uses the same mechanism as other Linux applications

## Architecture

The keyring integration consists of three components:

1. **KeyringConfigurationProvider**: Retrieves secrets from the keyring during application startup
2. **KeyringConfigurationSource**: Configuration source that integrates with ASP.NET Core's configuration system
3. **KeyringConfigurationExtensions**: Extension methods for clean API usage

The certificate password is retrieved automatically when the application starts and integrated into the configuration pipeline, making it available to `ApplicationConfiguration` just like any other configuration value.

## Setup

### 1. Store Certificate Password in Keyring

Run the setup script to store your certificate password:

```bash
bash scripts/setup-keyring.sh
```

Or manually using `secret-tool`:

```bash
secret-tool store --label='AuthReverseProxy Certificate Password' \
    service AuthReverseProxy \
    account certificate-default
```

### 2. Verify Storage

Check that the password is stored correctly:

```bash
secret-tool lookup service AuthReverseProxy account certificate-default
```

### 3. Run the Application

The application will automatically retrieve the certificate password from the keyring on startup.

## Keyring Daemon

The GNOME Keyring daemon must be running for the application to retrieve secrets. In the devcontainer, you can start it with:

```bash
eval $(dbus-launch --sh-syntax)
eval $(gnome-keyring-daemon --start --components=secrets)
```

For production deployments, ensure the keyring daemon is started as part of your service initialization.

## Troubleshooting

### Password not found

If you see "Warning: No secret found in keyring", ensure:

1. The keyring daemon is running
2. You've stored the password using the correct service/account names
3. The D-Bus session bus is available

### Permission errors

Ensure the application process has permission to access the keyring daemon and D-Bus session bus.

## Advanced Configuration

You can customize the keyring lookup parameters in `Program.cs`:

```csharp
builder.Configuration.AddKeyring(
    service: "MyCustomService",
    account: "my-certificate",
    configKey: "CertificatePassword"
);
```

## Security Considerations

- The keyring daemon encrypts secrets at rest using your login password
- Secrets are only accessible to processes running under your user account
- The keyring is unlocked when you log in and locks when you log out
- For automated services, consider using a dedicated keyring with a fixed password set via environment variables
