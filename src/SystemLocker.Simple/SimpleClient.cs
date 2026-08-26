using System.Text;
using SystemLocker.Simple.Hwid;

namespace SystemLocker.Simple;

/// <summary>The outcome of a key-expiration lookup.</summary>
public sealed class Expiration
{
    /// <summary>Permanent keys never expire (<c>"Never"</c>).</summary>
    public required bool Permanent { get; init; }

    /// <summary>The formatted UTC expiry string (for example
    /// <c>"2026-08-15 12:00:00 UTC"</c>). <c>"Never"</c> for permanent keys.</summary>
    public required string ExpiresAt { get; init; }
}

/// <summary>The outcome of a variable lookup.</summary>
public sealed class VariableValue
{
    /// <summary>False when the variable is missing, protected, or the key
    /// check failed.</summary>
    public required bool Found { get; init; }

    /// <summary>The variable contents when <see cref="Found"/> — including a
    /// literal <c>"false"</c> value.</summary>
    public string Value { get; init; } = "";
}

/// <summary>The outcome of a self-service HWID reset request.</summary>
public enum ResetOutcome
{
    /// <summary>The HWID was cleared.</summary>
    Granted,

    /// <summary>Self-service resets are disabled for the system (or the key
    /// is not eligible).</summary>
    Denied,

    /// <summary>The 30-day cooldown is still running.</summary>
    TooSoon,
}

/// <summary>
/// Stateless Simple client: one <c>POST /auth</c> per check, no sessions, no
/// signatures. One client per system; thread-safe. Success is reported only
/// when the server answers literally <c>true</c> — everything else throws a
/// <see cref="SimpleError"/>.
/// </summary>
public sealed class SimpleClient
{
    // The slice of the SL-HWID session the client needs; the indirection
    // keeps the module swappable in tests without exposing test hooks
    // publicly.
    internal interface ISlHwidSession
    {
        string Hwid { get; }
        void Commit();
    }

    private sealed class ModuleSlHwidSession : ISlHwidSession
    {
        private readonly SLHwidSession _session;

        public ModuleSlHwidSession(SLHwidSession session)
        {
            _session = session;
        }

        public string Hwid => _session.Hwid;
        public void Commit() => _session.Commit();
    }

    // Swappable in tests to drive the SL-HWID module without touching real
    // hardware or storage; a null value selects the real module.
    internal static Func<SLHwidOptions, ISlHwidSession>? SlHwidPrepareOverride { get; set; }

    private readonly SimpleConfig _config;
    private readonly IHttpClient _http;
    private readonly string? _legacyHwid; // eagerly derived when Hwid is empty and mode is "legacy"
    private readonly object _stateLock = new();
    private ISlHwidSession? _slHwidSession;

    /// <exception cref="SimpleError">when the configuration is invalid.</exception>
    public SimpleClient(SimpleConfig config, IHttpClient? http = null)
    {
        if (config.HwidMode != "legacy" && config.HwidMode != "sl-hwid")
        {
            throw new SimpleError(ErrorKind.Configuration, "HWID mode must be \"legacy\" or \"sl-hwid\".");
        }
        if (config.Hwid.Length == 0 && config.HwidMode == "legacy")
        {
            // An explicit hwid always wins. With an empty hwid the default
            // "sl-hwid" mode defers to the module at authentication time so a
            // client that never authenticates persists nothing; the opt-in
            // "legacy" mode derives the hardware hash eagerly instead.
            try
            {
                _legacyHwid = HwidCollector.DeviceHwid();
            }
            catch (Exception error) when (error is InvalidOperationException or NotSupportedException)
            {
                throw new SimpleError(ErrorKind.Configuration,
                    $"Could not derive the default hardware ID: {error.Message}. Supply a custom HWID or use \"1\" to disable device checks.");
            }
        }
        if (config.SystemId.Length == 0)
        {
            throw new SimpleError(ErrorKind.Configuration, "System ID must not be empty.");
        }
        if (config.Version.Length == 0)
        {
            throw new SimpleError(ErrorKind.Configuration, "Version must not be empty.");
        }
        if (!config.BaseUrl.StartsWith("https://", StringComparison.Ordinal))
        {
            throw new SimpleError(ErrorKind.Configuration, "Base URL must use HTTPS.");
        }
        _config = config;
        _http = http ?? new DefaultHttpClient(config.RequestTimeout, config.UserAgent);
    }

    public SimpleConfig Config => _config;

    internal IHttpClient Transport => _http;

    internal string Endpoint(string path) => _config.BaseUrl.TrimEnd('/') + path;

    /// <summary>The management sub-API. Requires
    /// <see cref="SimpleConfig.ApiKey"/>.</summary>
    public Management Management => new(this);

    // ── authentication ───────────────────────────────────────────────

    /// <summary>Checks a license key (key-only mode). Returns true only when
    /// the server answers literally <c>true</c>.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<bool> AuthenticateWithKeyAsync(string licenseKey, CancellationToken cancellationToken = default)
    {
        var fields = BaseFields();
        fields["key"] = licenseKey;
        return await AuthenticateAsync(fields, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Checks username + password credentials (account mode).</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<bool> AuthenticateWithPasswordAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        var fields = BaseFields();
        fields["username"] = username;
        fields["password"] = password;
        return await AuthenticateAsync(fields, cancellationToken).ConfigureAwait(false);
    }

    private async Task<bool> AuthenticateAsync(Dictionary<string, string> fields, CancellationToken cancellationToken)
    {
        var (body, _) = await RequestAsync("/auth", fields, cancellationToken).ConfigureAwait(false);
        if (body == "true")
        {
            // The server accepted this identity on this device.
            CommitHwid();
            return true;
        }
        throw Reasons.Classify(body);
    }

    // ── key expiration ───────────────────────────────────────────────

    /// <summary>Returns the expiry of a license key.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<Expiration> KeyExpirationForKeyAsync(string licenseKey, CancellationToken cancellationToken = default)
    {
        var fields = BaseFields();
        fields["key"] = licenseKey;
        fields["intent"] = "expiration";
        return await ExpirationAsync(fields, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Returns the expiry of the authenticated user's key for this system.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<Expiration> KeyExpirationForPasswordAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        var fields = BaseFields();
        fields["username"] = username;
        fields["password"] = password;
        fields["intent"] = "expiration";
        return await ExpirationAsync(fields, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Expiration> ExpirationAsync(Dictionary<string, string> fields, CancellationToken cancellationToken)
    {
        var (body, response) = await RequestAsync("/auth", fields, cancellationToken).ConfigureAwait(false);
        // A successful intent response carries auth: true; failures carry the
        // reason in auth (and the body).
        if (response.Header("auth") != "true")
        {
            throw Reasons.Classify(body);
        }
        if (body == "Never" || body == "N/A")
        {
            return new Expiration { Permanent = true, ExpiresAt = body };
        }
        return new Expiration { Permanent = false, ExpiresAt = body };
    }

    // ── variables ────────────────────────────────────────────────────

    /// <summary>
    /// Fetches a server-side variable. Pass a license key when the variable
    /// is protected.
    /// </summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<VariableValue> GetVariableAsync(string name, string? licenseKey = null, CancellationToken cancellationToken = default)
    {
        // The variable endpoint takes no version/hwid/digest: it is not an
        // authentication path.
        var fields = new Dictionary<string, string>
        {
            ["system"] = _config.SystemId,
            ["variable"] = name,
            ["clean"] = "1",
        };
        if (!string.IsNullOrEmpty(licenseKey))
        {
            fields["key"] = licenseKey;
        }
        var (body, response) = await RequestAsync("/auth/variable", fields, cancellationToken).ConfigureAwait(false);
        // The intent header disambiguates: "true" means the body is the value
        // (even when the value is literally "false"); "false" means missing,
        // protected, or unauthorized; anything else is an error reason.
        switch (response.Header("intent"))
        {
            case "true":
                return new VariableValue { Found = true, Value = body };
            case "false":
                return new VariableValue { Found = false };
            default:
                throw Reasons.Classify(body);
        }
    }

    // ── self-service HWID reset ──────────────────────────────────────

    /// <summary>Clears the HWID bound to a license key (self-service;
    /// per-system flag and a 30-day cooldown apply).</summary>
    /// <exception cref="SimpleError">on transport failures and credential
    /// denials; a completed reset returns an outcome instead.</exception>
    public async Task<ResetOutcome> ResetHwidForKeyAsync(string licenseKey, CancellationToken cancellationToken = default)
    {
        var fields = BaseFields();
        fields["key"] = licenseKey;
        fields["intent"] = "hwidreset";
        return await ResetHwidAsync(fields, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Clears the HWID of the authenticated user's key.</summary>
    /// <exception cref="SimpleError">on transport failures and credential
    /// denials; a completed reset returns an outcome instead.</exception>
    public async Task<ResetOutcome> ResetHwidForPasswordAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        var fields = BaseFields();
        fields["username"] = username;
        fields["password"] = password;
        fields["intent"] = "hwidreset";
        return await ResetHwidAsync(fields, cancellationToken).ConfigureAwait(false);
    }

    private async Task<ResetOutcome> ResetHwidAsync(Dictionary<string, string> fields, CancellationToken cancellationToken)
    {
        var (body, response) = await RequestAsync("/auth", fields, cancellationToken).ConfigureAwait(false);
        // Credential failures carry the reason in the auth header (and body).
        var authHeader = response.Header("auth");
        if (authHeader.Length > 0 && authHeader != "true")
        {
            throw Reasons.Classify(body);
        }
        // The intent header carries true/false/toosoon; the clean body carries
        // "1"/""/"toosoon".
        switch (response.Header("intent"))
        {
            case "true":
            case "1":
                return ResetOutcome.Granted;
            case "toosoon":
                return ResetOutcome.TooSoon;
            case "false":
            case "":
                if (body == "toosoon")
                {
                    return ResetOutcome.TooSoon;
                }
                if (body == "true" || body == "1")
                {
                    return ResetOutcome.Granted;
                }
                return ResetOutcome.Denied;
            default:
                throw new SimpleError(ErrorKind.UnknownReason,
                    "Unexpected hwidreset response.", response.Header("intent"));
        }
    }

    // ── Google SSO ───────────────────────────────────────────────────

    /// <summary>Returns the Google SSO portal URL for the configured system.</summary>
    public string GoogleSsoUrl() => GoogleSso.PortalUrl(_config.SystemId);

    // ── plumbing ─────────────────────────────────────────────────────

    private Dictionary<string, string> BaseFields()
    {
        var fields = new Dictionary<string, string>
        {
            ["system"] = _config.SystemId,
            ["version"] = _config.Version,
            ["hwid"] = ResolveHwid(),
            ["clean"] = "1",
        };
        if (_config.ProgramDigest is { Length: > 0 })
        {
            fields["digest"] = _config.ProgramDigest;
        }
        return fields;
    }

    // The hwid for outgoing requests. The legacy mode (and any explicit
    // value) was already resolved at construction; "sl-hwid" enrolls or
    // recovers lazily on the first request and caches the session so a later
    // successful authentication can commit a refresh.
    private string ResolveHwid()
    {
        if (_config.Hwid.Length > 0)
        {
            return _config.Hwid;
        }
        if (_config.HwidMode == "legacy")
        {
            return _legacyHwid!;
        }
        lock (_stateLock)
        {
            if (_slHwidSession is not null)
            {
                return _slHwidSession.Hwid;
            }
            var options = new SLHwidOptions
            {
                StorePath = _config.SLHwidStore ?? "",
                ExtraMandatory = _config.SLHwidExtraMandatory ?? Array.Empty<string>(),
            };
            ISlHwidSession session;
            try
            {
                session = SlHwidPrepareOverride?.Invoke(options)
                          ?? new ModuleSlHwidSession(SLHwid.Prepare(options));
            }
            catch (Exception error) when (error is SLHwidDriftException or SLHwidCorruptDataException or InvalidOperationException)
            {
                throw new SimpleError(ErrorKind.LocalFailure, $"SL-HWID unavailable: {error.Message}");
            }
            _slHwidSession = session;
            return session.Hwid;
        }
    }

    // Re-centers the SL-HWID shares on the hardware observed this launch. It
    // runs only after the server accepted an authentication; failures are
    // non-fatal — the next launch re-derives.
    private void CommitHwid()
    {
        ISlHwidSession? session;
        lock (_stateLock)
        {
            session = _slHwidSession;
        }
        try
        {
            session?.Commit();
        }
        catch
        {
            // the next launch re-derives
        }
    }

    internal async Task<(string body, HttpExchange response)> RequestAsync(string path, IReadOnlyDictionary<string, string> fields, CancellationToken cancellationToken)
    {
        var response = await _http.PostFormAsync(Endpoint(path), fields, cancellationToken).ConfigureAwait(false);
        if (!response.Ok)
        {
            if (response.TransportError is not null)
            {
                throw new SimpleError(ErrorKind.Transport, $"request failed: {response.TransportError}");
            }
            var body = Encoding.UTF8.GetString(response.Body).Trim();
            throw new SimpleError(ErrorKind.Transport, $"server returned HTTP {response.StatusCode}: {body}");
        }
        return (Encoding.UTF8.GetString(response.Body).Trim(), response);
    }
}
