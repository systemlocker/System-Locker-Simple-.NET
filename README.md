# System Locker Simple — .NET

Official C#/.NET 8+ client for the **System Locker Simple** protocol
(`POST /auth`): one request, one answer. No sessions, no heartbeats, no
signatures — the right fit when the machine running the check is one you
control (Threat Model 2). For software distributed to untrusted machines, use
a **Bedrock** client instead: it verifies an Ed25519 signature on every
response.

## Install

```sh
dotnet add package SystemLocker.Simple
```

No NuGet dependencies — the client is pure BCL.

## Quickstart

```csharp
using SystemLocker.Simple;

var config = new SimpleConfig
{
    SystemId = "abcdefghijklmnopqrst", // from the dashboard
    Version = "1.0.0",
    // Hwid stays unset: the default SL-HWID identity, shared with a Bedrock
    // program on the same machine. Use "1" to disable device locking.
};

var client = new SimpleClient(config);

if (!await client.AuthenticateWithKeyAsync("SL-XXXX-XXXX-XXXX"))
    return; // rejected — block the action
// …run the gated action…
```

`AuthenticateWithKeyAsync` returns `true` only for a literal `true` answer.
Everything else throws `SimpleError` — inspect `error.Kind` and
`error.Reason`:

| Kind            | Meaning                                                         |
| --------------- | --------------------------------------------------------------- |
| `Configuration` | invalid local configuration; no request was sent                |
| `Transport`     | the HTTP exchange failed or returned a non-2xx status           |
| `Server`        | the server reported an internal error (`dbe`)                   |
| `Denied`        | license denial (`frozen`, `hwid banned`, `expired key`, …)      |
| `SSO`           | Google-SSO account; `GoogleSso.Link(error)` extracts the portal |
| `LocalFailure`  | the opt-in SL-HWID device identity could not be produced        |
| `UnknownReason` | the server emitted a new reason; the raw string is carried      |

## Operations

| Operation                          | Method                                                                      |
| ---------------------------------- | --------------------------------------------------------------------------- |
| Check a license key                | `AuthenticateWithKeyAsync(key)`                                             |
| Check username + password          | `AuthenticateWithPasswordAsync(user, pass)`                                 |
| Key expiry (`Never` or a UTC date) | `KeyExpirationForKeyAsync` / `…ForPasswordAsync`                            |
| Server-side variable               | `GetVariableAsync(name, key?)`                                              |
| Self-service HWID reset            | `ResetHwidForKeyAsync` / `…ForPasswordAsync` → `Granted`/`Denied`/`TooSoon` |

## Management API (server-side tooling)

```csharp
var config = new SimpleConfig { SystemId = "…", Version = "1.0.0", ApiKey = "…" };
var client = new SimpleClient(config);

int count = await client.Management.RedeemedUserCountAsync();
string keys = await client.Management.GenerateKeysAsync(KeyExpiry.OneMonth, 10, "june-batch");
```

`Management` wraps `POST /api/v1`: key status/expiration, HWID resets (single
or whole-system), key generation, bans, expiry adjustment. The API key grants
all of it — keep it on servers you control.

## Google SSO (account authentication)

Accounts created through Google sign-in have no local password on the server.
A `username`/`password` check for such an account fails with an `SSO` error
whose reason embeds the portal URL where the user completes Google sign-in and
receives a system-specific password (valid 180 days) to use as their account
password. There is no callback; the user transcribes the generated password
into your login form and you simply retry.

Deliver the portal link to your user through your own channel (API response,
email, chat).

```csharp
try
{
    await client.AuthenticateWithPasswordAsync(username, password);
}
catch (SimpleError error) when (error.Kind == ErrorKind.SSO)
{
    // sso / ssoexp / ssowrong — the portal URL is embedded in the error.
    string portal = GoogleSso.Link(error);
    SendToUser(user, portal); // your channel: API response, email, chat…
}
```

`GoogleSso.PortalUrl(systemId)` (or `client.GoogleSsoUrl()`) builds the same
portal URL before any denial, if you already know the account signs in
through Google.

## Device identifiers (HWID)

The default derivation is the fault-tolerant **SL-HWID** module:
`HwidMode = "sl-hwid"` (the default). The HWID comes from a random key locked
behind threshold secret sharing instead of hashing hardware directly. It is
fault tolerant and cross platform (Windows, macOS, Linux), combines
**14 hardware factors**, and any two of them can fail or change without
changing the HWID; drifted factors are quietly re-absorbed after each
successful authentication. The module's own persisted value is hard-locked,
so copied state cannot stand in for changed hardware.

Things to know:

- **Storage is shared.** The enrollment lives in one per-machine location
  (the registry on Windows, an application-support directory elsewhere),
  shared by every System Locker client on the device. Configure
  `SLHwidStore` only when you deliberately need separate device state.
- **Re-activation exists.** If hardware drifts past the recovery threshold,
  requests fail with a `LocalFailure` error and the user needs a reset.

SL-HWID is the natural fit for a **launcher**: a Simple-based launcher that
opens a Bedrock-protected program reports exactly the HWID the Bedrock client
reports, because both share the same per-machine enrollment. The key the user
already activated in the launcher works for the protected program too — one
device, one HWID, no `hwid` mismatch between the two.

SL-HWID changes the device identifier only. It does not change what the
Simple protocol guarantees: responses are still unsigned, so only use this
client on machines you control.

### Plain hardware hash (legacy), opt-in

`HwidMode = "legacy"` restores the plain hardware-factor hash used by the
Go, Node.js, and Python Simple clients: the machine GUID, hardware UUID,
CPU id, and MAC, normalized, joined in a fixed order, and hashed with
SHA-256 (base64url). It is the weaker option — the hash over-fits a handful
of hardware values, so swapping a disk or NIC — or cloning the machine into
a VM — changes the HWID and forces your user through a device reset.

A developer-supplied stable value works as well as either mode:

```csharp
var config = new SimpleConfig { SystemId = "…", Version = "1.0.0", Hwid = MyStableId() };
```

Set `Hwid = "1"` only to explicitly disable device locking. An explicit
`Hwid` value (including `"1"`) always wins over both modes.

## Security

> [!WARNING]
> Watch this repository (Watch → Custom → Releases) and update your
> dependency when a release ships: releases regularly add security
> enhancements.

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately through the
System Locker support channels, not via public issues.
