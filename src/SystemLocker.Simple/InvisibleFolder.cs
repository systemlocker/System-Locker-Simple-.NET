using System.Text.Json;

namespace SystemLocker.Simple;

/// <summary>Selects how an Invisible Folder download authorizes against the
/// file's protection. Use exactly one factory; <see cref="None"/> downloads a
/// public or hidden file.</summary>
public sealed class InvisibleFolderCredential
{
    private readonly string? _filePassword;
    private readonly string? _licenseKey;
    private readonly string? _username;
    private readonly string? _password;

    private InvisibleFolderCredential(string? filePassword = null, string? licenseKey = null, string? username = null, string? password = null)
    {
        _filePassword = filePassword;
        _licenseKey = licenseKey;
        _username = username;
        _password = password;
    }

    /// <summary>Downloads a public or hidden file (no credential).</summary>
    public static InvisibleFolderCredential None { get; } = new();

    /// <summary>Unlocks a password-protected file.</summary>
    public static InvisibleFolderCredential WithFilePassword(string filePassword) => new(filePassword: filePassword);

    /// <summary>Unlocks a System Locker Simple file with a license key.</summary>
    public static InvisibleFolderCredential WithKey(string licenseKey) => new(licenseKey: licenseKey);

    /// <summary>Unlocks a System Locker Simple file with username and password.</summary>
    public static InvisibleFolderCredential WithUsernamePassword(string username, string password) => new(username: username, password: password);

    internal IReadOnlyDictionary<string, string> Headers()
    {
        var headers = new Dictionary<string, string>();
        if (_filePassword is not null)
        {
            headers["X-Invisiblefolder-Password"] = _filePassword;
        }
        if (_licenseKey is not null)
        {
            headers["X-Systemlocker-Key"] = _licenseKey;
        }
        if (_username is not null)
        {
            headers["X-Systemlocker-Username"] = _username;
            headers["X-Systemlocker-Password"] = _password ?? "";
        }
        return headers;
    }
}

/// <summary>A file description plus its metadata entries.</summary>
public sealed class InvisibleFolderMetadata
{
    public required string Id { get; init; }
    public required string ReferenceId { get; init; }
    public required string Name { get; init; }
    public required string MimeType { get; init; }
    public required long Size { get; init; }
    public required long Downloads { get; init; }
    public required string UploadedAt { get; init; }
    public required long PermissionTypeId { get; init; }
    public required IReadOnlyDictionary<string, (string Value, string? CreatedAt)> Values { get; init; }
}

/// <summary>The outcome of <see cref="InvisibleFolder.DownloadIfNewAsync"/>.</summary>
public sealed class DownloadIfNewResult
{
    public bool Downloaded { get; init; }
    public required string Revision { get; init; }
    public required InvisibleFolderMetadata Metadata { get; init; }
    public byte[]? Bytes { get; init; }
    public string? Destination { get; init; }
}

/// <summary>Downloads files from Invisible Folder using the end user's own
/// credentials. The token-based Advanced permission is a Bedrock feature and
/// is intentionally absent here. Access it through
/// <see cref="SimpleClient.InvisibleFolder"/>.</summary>
public sealed class InvisibleFolder
{
    private const string RevisionsKey = "__revisions";
    private readonly SimpleClient _client;

    internal InvisibleFolder(SimpleClient client) => _client = client;

    private void CheckPrerequisites(string referenceId)
    {
        if (!_client.Config.InvisibleFolderBaseUrl.StartsWith("https://", StringComparison.Ordinal))
        {
            throw new SimpleError(ErrorKind.Configuration, "Invisible Folder base URL must use HTTPS.");
        }
        if (referenceId.Length is < 4 or > 128 || !referenceId.All(static c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-'))
        {
            throw new SimpleError(ErrorKind.Configuration, "Invisible Folder reference ID must be 4 through 128 URL-safe characters.");
        }
    }

    private string Endpoint(string prefix, string referenceId) =>
        _client.Config.InvisibleFolderBaseUrl.TrimEnd('/') + prefix + referenceId;

    /// <summary>Downloads a file into memory. Pass <paramref name="credential"/>
    /// matching the file's protection; <c>null</c> downloads a public or hidden
    /// file.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<byte[]> DownloadAsync(string referenceId, InvisibleFolderCredential? credential = null, CancellationToken cancellationToken = default)
    {
        CheckPrerequisites(referenceId);
        // The download route is a plain GET; credentials travel in headers
        // because GET request bodies are not supported.
        var headers = new Dictionary<string, string> { ["X-Invisiblefolder-Download"] = "1" };
        foreach (var (name, value) in (credential ?? InvisibleFolderCredential.None).Headers())
        {
            headers[name] = value;
        }
        var response = await _client.Transport.GetAsync(Endpoint("/a/", referenceId), headers, cancellationToken).ConfigureAwait(false);
        if (!response.Ok)
        {
            var message = ParseErrorMessage(response);
            throw message is null
                ? TransportError("download", response)
                : new SimpleError(ErrorKind.Transport, $"Invisible Folder download failed: {message}");
        }
        return response.Body;
    }

    /// <summary>Downloads a file and writes it to destination
    /// (unencrypted).</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<string> DownloadToFileAsync(string referenceId, string destination, InvisibleFolderCredential? credential = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(destination))
        {
            throw new SimpleError(ErrorKind.Configuration, "Invisible Folder download destination cannot be empty.");
        }
        var payload = await DownloadAsync(referenceId, credential, cancellationToken).ConfigureAwait(false);
        try
        {
            await File.WriteAllBytesAsync(destination, payload, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw new SimpleError(ErrorKind.LocalFailure, "Could not write Invisible Folder download destination.");
        }
        return destination;
    }

    /// <summary>Fetches a file's description and metadata entries.
    /// <paramref name="keys"/> selects specific entries; null fetches all.
    /// Requires <see cref="SimpleConfig.InvisibleFolderApiKey"/> to read
    /// metadata for API Available, Password Protected, and System Locker
    /// Simple files.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<InvisibleFolderMetadata> GetMetadataAsync(string referenceId, IReadOnlyList<string>? keys = null, CancellationToken cancellationToken = default)
    {
        CheckPrerequisites(referenceId);

        IReadOnlyDictionary<string, string> headers =
            _client.Config.InvisibleFolderApiKey is { Length: > 0 } apiKey
                ? new Dictionary<string, string> { ["X-Api-Key"] = apiKey }
                : new Dictionary<string, string>();

        var url = Endpoint("/api/v1/files/", referenceId) + "/metadata";
        if (keys is { Count: > 0 })
        {
            url += "?keys[]=" + string.Join("&keys[]=", keys.Select(Uri.EscapeDataString));
        }

        var response = await _client.Transport.GetAsync(url, headers, cancellationToken).ConfigureAwait(false);
        if (!response.Ok)
        {
            var message = ParseErrorMessage(response);
            throw message is null
                ? TransportError("metadata request", response)
                : new SimpleError(ErrorKind.Transport, $"Invisible Folder metadata request failed: {message}");
        }
        return ParseMetadata(response.Body);
    }

    /// <summary>Downloads only when the file's <c>__revisions</c> metadata
    /// differs from <paramref name="knownRevision"/>. With a destination the
    /// file is written to disk; without one it is returned in memory.</summary>
    /// <exception cref="SimpleError">on any failure.</exception>
    public async Task<DownloadIfNewResult> DownloadIfNewAsync(string referenceId, string knownRevision = "", string? destination = null, InvisibleFolderCredential? credential = null, CancellationToken cancellationToken = default)
    {
        var metadata = await GetMetadataAsync(referenceId, new[] { RevisionsKey }, cancellationToken).ConfigureAwait(false);
        if (!metadata.Values.TryGetValue(RevisionsKey, out var revision))
        {
            throw new SimpleError(ErrorKind.Server, "Invisible Folder metadata did not contain __revisions.");
        }

        if (knownRevision != "" && knownRevision == revision.Value)
        {
            return new DownloadIfNewResult { Downloaded = false, Revision = revision.Value, Metadata = metadata };
        }

        if (destination is not null)
        {
            var saved = await DownloadToFileAsync(referenceId, destination, credential, cancellationToken).ConfigureAwait(false);
            return new DownloadIfNewResult { Downloaded = true, Revision = revision.Value, Metadata = metadata, Destination = saved };
        }
        var bytes = await DownloadAsync(referenceId, credential, cancellationToken).ConfigureAwait(false);
        return new DownloadIfNewResult { Downloaded = true, Revision = revision.Value, Metadata = metadata, Bytes = bytes };
    }

    private static string? ParseErrorMessage(HttpExchange response)
    {
        try
        {
            var json = JsonSerializer.Deserialize<JsonElement>(response.Body);
            if (json.ValueKind == JsonValueKind.Object)
            {
                if (json.TryGetProperty("message", out var message) && message.ValueKind == JsonValueKind.String)
                {
                    return message.GetString();
                }
                if (json.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String)
                {
                    return error.GetString();
                }
            }
        }
        catch (JsonException)
        {
        }
        return null;
    }

    private static SimpleError TransportError(string action, HttpExchange response) =>
        response.TransportError is not null
            ? new SimpleError(ErrorKind.Transport, $"Invisible Folder {action} failed: {response.TransportError}")
            : new SimpleError(ErrorKind.Transport, $"Invisible Folder {action} returned HTTP {response.StatusCode}.");

    private static InvisibleFolderMetadata ParseMetadata(byte[] body)
    {
        JsonElement json;
        try
        {
            json = JsonSerializer.Deserialize<JsonElement>(body);
        }
        catch (JsonException)
        {
            throw new SimpleError(ErrorKind.Server, "Invisible Folder metadata JSON is invalid.");
        }
        var data = json.ValueKind == JsonValueKind.Object && json.TryGetProperty("data", out var dataElement)
            ? dataElement
            : throw new SimpleError(ErrorKind.Server, "Invisible Folder metadata response has the wrong shape.");
        if (data.ValueKind != JsonValueKind.Object ||
            !data.TryGetProperty("file", out var file) || file.ValueKind != JsonValueKind.Object ||
            !data.TryGetProperty("metadata", out var metadataElement) || metadataElement.ValueKind != JsonValueKind.Object)
        {
            throw new SimpleError(ErrorKind.Server, "Invisible Folder metadata response has the wrong shape.");
        }

        string String(string name) =>
            file.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String
                ? element.GetString()!
                : throw new SimpleError(ErrorKind.Server, $"Invisible Folder file field '{name}' is missing or has the wrong type.");
        long Integer(string name) =>
            file.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out var value)
                ? value
                : throw new SimpleError(ErrorKind.Server, $"Invisible Folder file field '{name}' is missing or has the wrong type.");

        var values = new Dictionary<string, (string, string?)>();
        foreach (var entry in metadataElement.EnumerateObject())
        {
            if (entry.Value.ValueKind != JsonValueKind.Object ||
                !entry.Value.TryGetProperty("value", out var value) ||
                value.ValueKind != JsonValueKind.String)
            {
                throw new SimpleError(ErrorKind.Server, "Invisible Folder metadata entry has the wrong type.");
            }
            string? createdAt = null;
            if (entry.Value.TryGetProperty("created_at", out var createdAtElement) && createdAtElement.ValueKind != JsonValueKind.Null)
            {
                if (createdAtElement.ValueKind != JsonValueKind.String)
                {
                    throw new SimpleError(ErrorKind.Server, "Invisible Folder metadata creation time has the wrong type.");
                }
                createdAt = createdAtElement.GetString();
            }
            values[entry.Name] = (value.GetString()!, createdAt);
        }

        return new InvisibleFolderMetadata
        {
            Id = String("id"),
            ReferenceId = String("reference_id"),
            Name = String("name"),
            MimeType = String("mime_type"),
            Size = Integer("size"),
            Downloads = Integer("downloads"),
            UploadedAt = String("uploaded_at"),
            PermissionTypeId = Integer("permission_type_id"),
            Values = values,
        };
    }
}
