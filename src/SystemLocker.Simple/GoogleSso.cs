using System.Text;

namespace SystemLocker.Simple;

/// <summary>Google SSO portal URL construction and link extraction.</summary>
public static class GoogleSso
{
    private const string Portal = "https://systemlocker.net/user/sso?system=";

    /// <summary>
    /// Returns the Google SSO portal URL for a system. After the user signs
    /// in there, the portal shows a system-specific password that is valid for
    /// 180 days and is then used as the account password.
    ///
    /// The Simple protocol targets trusted machines (typically servers), so
    /// the library deliberately stops at the URL: route it to your user
    /// through your own channel (API response, email, chat) rather than
    /// expecting a browser on the host.
    /// </summary>
    public static string PortalUrl(string systemId) => Portal + EscapeSystemId(systemId);

    /// <summary>Returns the portal URL embedded in an <c>sso</c>/<c>ssoexp</c>/<c>ssowrong</c>
    /// denial, or an empty string for any other error.</summary>
    public static string Link(SimpleError error)
    {
        if (error.Kind != ErrorKind.SSO)
        {
            return "";
        }
        var space = error.Reason.IndexOf(' ');
        return space >= 0 ? error.Reason[(space + 1)..] : "";
    }

    // Percent-encodes everything except unreserved characters, matching the
    // server's rawurlencode so every client builds byte-identical portal URLs.
    private static string EscapeSystemId(string value)
    {
        var encoded = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(value))
        {
            if (b is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z'
                or >= (byte)'0' and <= (byte)'9'
                or (byte)'-' or (byte)'_' or (byte)'.' or (byte)'~')
            {
                encoded.Append((char)b);
            }
            else
            {
                encoded.Append('%').Append(b.ToString("X2"));
            }
        }
        return encoded.ToString();
    }
}
