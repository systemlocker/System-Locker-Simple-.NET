// Quickstart shows the smallest working Simple integration.

using SystemLocker.Simple;

var config = new SimpleConfig
{
    SystemId = "abcdefghijklmnopqrst", // from the dashboard
    Version = "1.0.0",
    // Hwid stays unset: the default SL-HWID identity, shared with a Bedrock
    // program on the same machine. Use "1" to disable device locking.
};

var client = new SimpleClient(config);

try
{
    if (!await client.AuthenticateWithKeyAsync("SL-XXXX-XXXX-XXXX"))
    {
        Console.WriteLine("license rejected");
        return;
    }
}
catch (SimpleError error)
{
    Console.WriteLine($"check failed: {error.Kind} ({error.Reason})");
    return;
}
Console.WriteLine("license ok — run your protected action");

// Server-side variables, expiration, and self-service HWID resets:
var expiration = await client.KeyExpirationForKeyAsync("SL-XXXX-XXXX-XXXX");
Console.WriteLine($"expires: {expiration.ExpiresAt}");

var variable = await client.GetVariableAsync("feature_flags");
if (variable.Found)
{
    Console.WriteLine($"feature_flags = {variable.Value}");
}
