namespace SystemLocker.Simple;

/// <summary>
/// Configures a <see cref="SimpleClient"/>. One client per system. Property
/// defaults match the Bedrock .NET client; set at least
/// <see cref="SystemId"/> and <see cref="Version"/>.
/// </summary>
public sealed class SimpleConfig
{
    /// <summary>The system identifier from the developer dashboard. Required.</summary>
    public required string SystemId { get; set; }

    /// <summary>The client version reported to the server. Required.</summary>
    public required string Version { get; set; }

    /// <summary>Device identifier. Empty (the default) derives hardware factors
    /// according to <see cref="HwidMode"/>; use "1" to disable device locking.
    /// An explicit value always takes precedence over both modes.</summary>
    public string Hwid { get; set; } = "";

    /// <summary>How the device identifier is derived when <see cref="Hwid"/> is
    /// empty. The default is "sl-hwid": the SL-HWID fault-tolerant threshold
    /// module — the right choice for a launcher that gates access to a
    /// Bedrock-protected program, because it reports the same device identity
    /// the Bedrock client reports. Opt out with "legacy" to restore the plain
    /// hardware-factor hash used by the other Simple clients.</summary>
    public string HwidMode { get; set; } = "sl-hwid";

    /// <summary>Optionally redirects the SL-HWID module's storage to a
    /// directory (files on every platform); empty uses the platform default
    /// (the registry on Windows, an application-support directory elsewhere) —
    /// the same location the Bedrock clients use, so a Simple launcher and a
    /// Bedrock application share one device identity.</summary>
    public string? SLHwidStore { get; set; }

    /// <summary>Names additional hard-locked SL-HWID slots beyond the module's
    /// own persisted value (for example, <c>"machine_guid"</c>).</summary>
    public string[]? SLHwidExtraMandatory { get; set; }

    /// <summary>Per-request HTTP timeout.</summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>System Locker API root. HTTPS is enforced.</summary>
    public string BaseUrl { get; set; } = "https://systemlocker.net";

    /// <summary>User agent reported to the server.</summary>
    public string UserAgent { get; set; } = "systemlocker-simple-dotnet/0.1";

    /// <summary>Optional program digest, checked against the system's expected digest.</summary>
    public string? ProgramDigest { get; set; }

    /// <summary>Optional management API key; only needed for the
    /// <see cref="Management"/> sub-API.</summary>
    public string? ApiKey { get; set; }
}
