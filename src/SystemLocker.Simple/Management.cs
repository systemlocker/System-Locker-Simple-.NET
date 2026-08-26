namespace SystemLocker.Simple;

/// <summary>Expiry presets the server understands for key generation and
/// expiry adjustment.</summary>
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
/// Wraps the <c>POST /api/v1</c> management endpoint. It is independent of
/// the authentication protocol and is meant for your server-side tooling;
/// treat the API key as a secret. Access it through
/// <see cref="SimpleClient.Management"/>.
/// </summary>
public sealed class Management
{
    private readonly SimpleClient _client;

    internal Management(SimpleClient client)
    {
        _client = client;
    }

    /// <summary>Returns the number of redeemed keys for the system.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<int> RedeemedUserCountAsync(CancellationToken cancellationToken = default)
    {
        var body = await PostAsync(new Dictionary<string, string> { ["select"] = "users" }, cancellationToken).ConfigureAwait(false);
        if (!int.TryParse(body, out var count))
        {
            throw new SimpleError(ErrorKind.UnknownReason, $"non-numeric users response: {body}", body);
        }
        return count;
    }

    /// <summary>Returns the redemption status of a license key as a
    /// human-readable string forwarded from the server.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> KeyStatusAsync(string license, CancellationToken cancellationToken = default) =>
        PostAsync(new Dictionary<string, string> { ["select"] = "key", ["lkey"] = license }, cancellationToken);

    /// <summary>Returns the expiration date of a license key.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<Expiration> KeyExpirationAsync(string license, CancellationToken cancellationToken = default)
    {
        var body = await PostAsync(new Dictionary<string, string> { ["select"] = "expiration", ["lkey"] = license }, cancellationToken).ConfigureAwait(false);
        var lower = body.ToLowerInvariant();
        return new Expiration { Permanent = lower == "permanent" || lower == "never" || body == "0", ExpiresAt = body };
    }

    /// <summary>Resets the HWID of one key. <paramref name="asAdmin"/>
    /// bypasses the 30-day cooldown.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> ResetHwidAsync(string license, bool asAdmin = false, CancellationToken cancellationToken = default)
    {
        var fields = new Dictionary<string, string>
        {
            ["command"] = "hwidreset",
            ["license"] = license,
        };
        if (!asAdmin)
        {
            fields["as_admin"] = "false";
        }
        return PostAsync(fields, cancellationToken);
    }

    /// <summary>Resets the HWID of every key in the system. Use with care.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> ResetAllHwidsAsync(CancellationToken cancellationToken = default) =>
        PostAsync(new Dictionary<string, string> { ["command"] = "systemhwidreset" }, cancellationToken);

    /// <summary>
    /// Generates <paramref name="count"/> (1–100) license keys with the given
    /// expiry preset, optionally annotated with a note (≤250 characters). The
    /// response is the raw server body (typically the keys, one per line).
    /// </summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> GenerateKeysAsync(KeyExpiry expiry, int count, string note = "", CancellationToken cancellationToken = default)
    {
        if (count < 1 || count > 100)
        {
            throw new SimpleError(ErrorKind.Configuration, "count must be in [1, 100]");
        }
        if (note.Length > 250)
        {
            throw new SimpleError(ErrorKind.Configuration, "note must be at most 250 characters");
        }
        var fields = new Dictionary<string, string>
        {
            ["command"] = "genkeys",
            ["expire"] = ((int)expiry).ToString(),
            ["count"] = count.ToString(),
        };
        if (note.Length > 0)
        {
            fields["note"] = note;
        }
        return PostAsync(fields, cancellationToken);
    }

    /// <summary>Permanently deletes a key.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> BanKeyAsync(string license, CancellationToken cancellationToken = default) =>
        PostAsync(new Dictionary<string, string> { ["command"] = "bankey", ["license"] = license }, cancellationToken);

    /// <summary>
    /// Sets a key's expiry. <paramref name="newExpiry"/> is a date the server
    /// understands (for example <c>"2026-12-31"</c>), or <c>"0"</c> for
    /// permanent. <paramref name="timeZone"/> is an IANA timezone such as
    /// <c>"America/Chicago"</c>.
    /// </summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public Task<string> AdjustExpiryAsync(string license, string newExpiry, string timeZone, CancellationToken cancellationToken = default) =>
        PostAsync(new Dictionary<string, string>
        {
            ["command"] = "adjustexpiry",
            ["license"] = license,
            ["newexpiry"] = newExpiry,
            ["tz"] = timeZone,
        }, cancellationToken);

    private async Task<string> PostAsync(Dictionary<string, string> fields, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(_client.Config.ApiKey))
        {
            throw new SimpleError(ErrorKind.Configuration, "management API key not configured");
        }
        fields["key"] = _client.Config.ApiKey;
        var (body, _) = await _client.RequestAsync("/api/v1", fields, cancellationToken).ConfigureAwait(false);
        return body;
    }
}
