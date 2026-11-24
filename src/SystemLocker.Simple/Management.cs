using System.Text.Json;

namespace SystemLocker.Simple;

/// <summary>Expiry presets for key generation. Duration presets start at
/// redemption.</summary>
public enum KeyExpiry
{
    /// <summary>Never expires.</summary>
    Permanent = 0,
    OneDay = 1,
    OneWeek = 2,
    OneMonth = 3,
    ThreeMonths = 4,
    OneYear = 5,
}

/// <summary>
/// Wraps the Management API v2 (<c>/api/v2</c>). It is independent of the
/// authentication protocol and is meant for your server-side tooling.
/// <see cref="SimpleConfig.ApiKey"/> must hold a scoped v2 bearer credential
/// for this system; treat it as a secret. Access it through
/// <see cref="SimpleClient.Management"/>.
/// </summary>
public sealed class Management
{
    // Duration in seconds for each KeyExpiry preset, indexed by its value.
    // Index 0 (permanent) is never sent as a duration.
    private static readonly int[] PresetSeconds = [0, 86400, 604800, 2592000, 7776000, 31536000];

    private readonly SimpleClient _client;

    internal Management(SimpleClient client)
    {
        _client = client;
    }

    private string SystemPath => "/systems/" + Uri.EscapeDataString(_client.Config.SystemId);

    private string KeyPath(string license) => SystemPath + "/keys/" + Uri.EscapeDataString(license);

    /// <summary>
    /// Calls any v2 resource path (relative to <c>/api/v2</c>, for example
    /// <c>/permissions</c> or <c>/systems/{id}/nightflyer</c>) and returns the
    /// response's JSON <c>data</c>. <paramref name="data"/> is serialized as
    /// the JSON body; POST, PUT and PATCH without data send an empty object.
    /// Mutations are never retried.
    /// </summary>
    /// <exception cref="SimpleError">on any failure. For a non-2xx response,
    /// <see cref="SimpleError.Reason"/> is the server's error code (for
    /// example <c>INSUFFICIENT_SCOPE</c>).</exception>
    public async Task<JsonElement> RequestAsync(string method, string path, object? data = null, CancellationToken cancellationToken = default)
    {
        var credential = _client.Config.ApiKey;
        if (string.IsNullOrEmpty(credential) || credential.Contains('\r') || credential.Contains('\n'))
            throw new SimpleError(ErrorKind.Configuration, "a management bearer credential is required");
        if (method is not ("GET" or "POST" or "PUT" or "PATCH" or "DELETE") || !path.StartsWith('/') || path.StartsWith("//") || path.Contains('#'))
            throw new SimpleError(ErrorKind.Configuration, "invalid management method or resource path");
        // The server requires a JSON Content-Type on every mutation, even one
        // without fields.
        if (data is null && method is ("POST" or "PUT" or "PATCH"))
        {
            data = new { };
        }
        var response = await _client.Transport.RequestJsonAsync(method, _client.Config.BaseUrl.TrimEnd('/') + "/api/v2" + path,
            data is null ? null : JsonSerializer.Serialize(data),
            new Dictionary<string, string> { ["Authorization"] = "Bearer " + credential, ["Accept"] = "application/json" }, cancellationToken).ConfigureAwait(false);
        if (response.TransportError is not null) throw new SimpleError(ErrorKind.Transport, response.TransportError);

        JsonElement root;
        try
        {
            using var document = JsonDocument.Parse(response.Body);
            root = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw new SimpleError(ErrorKind.Transport, $"management returned invalid JSON (HTTP {response.StatusCode})");
        }

        if (!response.Ok)
        {
            // Fall back to the HTTP status when the error envelope is absent
            // or malformed, so the caller still sees a useful message.
            string? code = null, message = null;
            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object)
            {
                if (error.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String) code = c.GetString();
                if (error.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String) message = m.GetString();
            }
            throw new SimpleError(ErrorKind.Transport, string.IsNullOrEmpty(message) ? $"management HTTP {response.StatusCode}" : message, code ?? "");
        }
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("data", out var payload))
            throw new SimpleError(ErrorKind.UnknownReason, "management response is missing data");
        return payload;
    }

    // Runs a request and parses its data; any shape mismatch becomes a
    // transport error instead of leaking a System.Text.Json exception.
    private async Task<T> ReadAsync<T>(string method, string path, Func<JsonElement, T> parse, object? data = null, CancellationToken cancellationToken = default)
    {
        var result = await RequestAsync(method, path, data, cancellationToken).ConfigureAwait(false);
        try
        {
            return parse(result);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException)
        {
            throw new SimpleError(ErrorKind.Transport, "invalid management data");
        }
    }

    private async Task<string> RawAsync(string method, string path, object? data, CancellationToken cancellationToken) =>
        (await RequestAsync(method, path, data, cancellationToken).ConfigureAwait(false)).GetRawText();

    /// <summary>Returns the scopes granted to the configured credential. Requires no scope.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string[]> PermissionsAsync(CancellationToken cancellationToken = default) =>
        ReadAsync("GET", "/permissions", data => data.GetProperty("scopes").EnumerateArray()
            .Select(scope => scope.GetString() ?? throw new JsonException()).ToArray(), cancellationToken: cancellationToken);

    /// <summary>Returns the system's user count (accounts plus key-only
    /// redemptions). The server refreshes it periodically, so it can lag
    /// behind recent redemptions. Requires <c>systems.read</c>.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<int> RedeemedUserCountAsync(CancellationToken cancellationToken = default) =>
        ReadAsync("GET", SystemPath + "/statistics", data =>
        {
            var count = data.GetProperty("total_users").GetInt32();
            return count >= 0 ? count : throw new JsonException();
        }, cancellationToken: cancellationToken);

    /// <summary>Returns how a key is claimed: <c>user</c> (attached to an
    /// account), <c>mikros</c> (redeemed without an account) or
    /// <c>unclaimed</c>. Requires <c>keys.read</c>.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> KeyStatusAsync(string license, CancellationToken cancellationToken = default) =>
        ReadAsync("GET", KeyPath(license), data =>
        {
            var claim = data.GetProperty("claim_type");
            return claim.ValueKind == JsonValueKind.String ? claim.GetString()! : throw new JsonException();
        }, cancellationToken: cancellationToken);

    /// <summary>Returns a key's expiry. <see cref="Expiration.ExpiresAt"/> is
    /// an RFC 3339 UTC timestamp, or empty when the key has no fixed expiry.
    /// <see cref="Expiration.Permanent"/> is only reported for redeemed keys:
    /// an unredeemed duration key has no timestamp yet either. Requires
    /// <c>keys.read</c>.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<Expiration> KeyExpirationAsync(string license, CancellationToken cancellationToken = default) =>
        ReadAsync("GET", KeyPath(license), data =>
        {
            var expiry = data.GetProperty("expires_at").GetString();
            var redeemed = data.GetProperty("redeemed_at").GetString();
            return new Expiration { Permanent = expiry is null && redeemed is not null, ExpiresAt = expiry ?? "" };
        }, cancellationToken: cancellationToken);

    /// <summary>Administrative HWID reset of one key (no cooldown). Returns
    /// the key's details as JSON. Self-service resets use
    /// <see cref="SimpleClient.ResetHwidForKeyAsync"/>. Requires
    /// <c>keys.update</c>.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> ResetHwidAsync(string license, CancellationToken cancellationToken = default) =>
        RawAsync("POST", KeyPath(license) + "/hwid-reset", null, cancellationToken);

    /// <summary>Resets the HWID of every key in the system and returns
    /// <c>{"updated":count}</c>. Use with care. Requires <c>keys.update</c>.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> ResetAllHwidsAsync(CancellationToken cancellationToken = default) =>
        RawAsync("POST", SystemPath + "/keys/hwid-reset", null, cancellationToken);

    /// <summary>
    /// Generates <paramref name="count"/> (1–100) license keys with the given
    /// expiry preset, optionally annotated with a note (≤250 characters), and
    /// returns them one per line. Duration presets start at redemption.
    /// Requires <c>keys.create</c>.
    /// </summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<string> GenerateKeysAsync(KeyExpiry expiry, int count, string note = "", CancellationToken cancellationToken = default)
    {
        if (count < 1 || count > 100) throw new SimpleError(ErrorKind.Configuration, "count must be in [1, 100]");
        if (note.Length > 250) throw new SimpleError(ErrorKind.Configuration, "note must be at most 250 characters");
        if ((int)expiry < 0 || (int)expiry >= PresetSeconds.Length) throw new SimpleError(ErrorKind.Configuration, "invalid expiry preset");
        object policy = expiry == KeyExpiry.Permanent ? new { type = "perpetual" } : new { type = "after_redemption", seconds = PresetSeconds[(int)expiry] };
        return await ReadAsync("POST", SystemPath + "/keys", data =>
            string.Join("\n", data.GetProperty("keys").EnumerateArray().Select(key => key.GetString() ?? throw new JsonException())),
            new { count, notes = note, expiry = policy }, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Permanently deletes a key and returns <c>{"deleted":true}</c>.
    /// Requires <c>keys.delete</c>.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> BanKeyAsync(string license, CancellationToken cancellationToken = default) =>
        RawAsync("DELETE", KeyPath(license), null, cancellationToken);

    /// <summary>Extends a key's expiry by a positive number of seconds and
    /// returns the key's details as JSON. Replaces the retired absolute-expiry
    /// adjustment, which has no v2 equivalent. Requires <c>keys.update</c>.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> AddTimeAsync(string license, long seconds, CancellationToken cancellationToken = default)
    {
        if (seconds <= 0) throw new SimpleError(ErrorKind.Configuration, "seconds must be a positive integer");
        return RawAsync("POST", KeyPath(license) + "/time", new { seconds }, cancellationToken);
    }
}
