namespace SystemLocker.Simple;

/// <summary>Error kinds, identical across the official Simple clients.</summary>
public enum ErrorKind
{
    /// <summary>The local configuration is invalid; no request was sent.</summary>
    Configuration,

    /// <summary>The HTTP exchange failed or returned a non-2xx status.</summary>
    Transport,

    /// <summary>The server reported an internal database error (reason <c>dbe</c>).</summary>
    Server,

    /// <summary>The server rejected the request for a known, license-related
    /// reason (frozen key, banned HWID, bad credentials…).</summary>
    Denied,

    /// <summary>The account requires Google SSO handling; the portal link is
    /// in the error (see <see cref="GoogleSso.Link"/>).</summary>
    SSO,

    /// <summary>A local subsystem needed by the request failed — currently
    /// only the opt-in SL-HWID module (for example hardware drifted past its
    /// recovery threshold, requiring re-activation).</summary>
    LocalFailure,

    /// <summary>The server returned a 2xx failure with a reason this library
    /// does not recognize; the raw reason is carried.</summary>
    UnknownReason,
}

/// <summary>Every client operation throws this; <see cref="Kind"/> categorizes
/// it and <see cref="Reason"/> carries the server's raw reason string.</summary>
public sealed class SimpleError : Exception
{
    public SimpleError(ErrorKind kind, string message, string reason = "") : base(
        reason.Length > 0 ? $"{kind}: {reason}" : message)
    {
        Kind = kind;
        Reason = reason;
    }

    public ErrorKind Kind { get; }

    /// <summary>The raw reason string from the server (empty for local failures).</summary>
    public string Reason { get; }
}

/// <summary>Maps the server's documented reason strings to typed errors.</summary>
internal static class Reasons
{
    private static readonly HashSet<string> DeniedReasons =
    [
        "no username", "no password", "no key", "no sys", "no hwid",
        "false", // missing version
        "not verified", "bad u/p", "bad key", "bad keys", "frozen", "paused",
        "destitute", "user limit", "hwid banned", "spoofsuspected", "hwid",
        "expired key", "outdated", "digest", "exp err big", "no var",
    ];

    public static SimpleError Classify(string reason)
    {
        if (reason == "dbe")
        {
            return new SimpleError(ErrorKind.Server, "The server reported an internal error.", reason);
        }
        if (reason == "sso" || (reason.Length > 4 && reason.StartsWith("sso ", StringComparison.Ordinal)))
        {
            return Sso("sso", reason);
        }
        if (reason.Length > 6 && reason.StartsWith("ssoexp", StringComparison.Ordinal))
        {
            return Sso("ssoexp", reason);
        }
        if (reason.Length > 8 && reason.StartsWith("ssowrong", StringComparison.Ordinal))
        {
            return Sso("ssowrong", reason);
        }
        if (DeniedReasons.Contains(reason))
        {
            return new SimpleError(ErrorKind.Denied, $"The request was rejected: {reason}.", reason);
        }
        // Unknown reasons (including enforcement-layer failures) still carry
        // their raw string.
        return new SimpleError(ErrorKind.UnknownReason, $"The server returned an unrecognized failure: {reason}", reason);
    }

    private static SimpleError Sso(string stage, string reason)
    {
        var link = "";
        if (reason.Length > stage.Length && reason[stage.Length] == ' ')
        {
            link = reason[(stage.Length + 1)..];
        }
        var message = stage switch
        {
            "sso" => "This account requires a Google SSO token; visit the link to create one.",
            "ssoexp" => "The Google SSO token expired; visit the link to renew it.",
            "ssowrong" => "The supplied password is not the Google SSO token; visit the link.",
            _ => "This account signs in through Google.",
        };
        return new SimpleError(ErrorKind.SSO, $"{message} Portal: {link}", reason);
    }
}
