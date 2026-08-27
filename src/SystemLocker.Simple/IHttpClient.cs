using System.Text;

namespace SystemLocker.Simple;

/// <summary>Transport-neutral HTTP response. Header keys are lowercase.</summary>
public sealed class HttpExchange
{
    public int StatusCode { get; init; }
    public byte[] Body { get; init; } = Array.Empty<byte>();
    public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public string? TransportError { get; init; }

    public bool Ok => TransportError is null && StatusCode is >= 200 and < 300;

    public string Header(string name) =>
        Headers.TryGetValue(name, out var value) ? value : "";
}

/// <summary>Abstraction over the protocol's HTTP operations; implement to
/// inject a fake transport in tests.</summary>
public interface IHttpClient
{
    Task<HttpExchange> PostFormAsync(string url, IEnumerable<KeyValuePair<string, string>> fields, CancellationToken cancellationToken = default);

    Task<HttpExchange> GetAsync(string url, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default);
}

/// <summary>Default transport over <see cref="HttpClient"/>.</summary>
public sealed class DefaultHttpClient : IHttpClient
{
    private const int MaxResponseBytes = 1024 * 1024;
    private readonly HttpClient _client;

    public DefaultHttpClient(TimeSpan timeout, string userAgent)
    {
        _client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = timeout };
        if (userAgent.Length > 0)
        {
            _client.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
        }
    }

    public async Task<HttpExchange> PostFormAsync(string url, IEnumerable<KeyValuePair<string, string>> fields, CancellationToken cancellationToken = default)
    {
        using var content = new FormUrlEncodedContent(fields);
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        return await SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    public async Task<HttpExchange> GetAsync(string url, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (headers is not null)
        {
            foreach (var (name, value) in headers)
            {
                request.Headers.TryAddWithoutValidation(name, value);
            }
        }
        return await SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpExchange> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.Content.Headers.ContentLength is > MaxResponseBytes)
            {
                return new HttpExchange { StatusCode = (int)response.StatusCode, TransportError = "response body exceeds 1 MiB limit" };
            }
            var body = await ReadBoundedBodyAsync(response.Content, cancellationToken).ConfigureAwait(false);
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, values) in response.Headers)
            {
                if (values.Any())
                {
                    headers[name] = string.Join(",", values);
                }
            }
            foreach (var (name, values) in response.Content.Headers)
            {
                if (values.Any() && !headers.ContainsKey(name))
                {
                    headers[name] = string.Join(",", values);
                }
            }
            return new HttpExchange { StatusCode = (int)response.StatusCode, Body = body, Headers = headers };
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException or InvalidDataException)
        {
            return new HttpExchange { TransportError = error.Message };
        }
    }

    private static async Task<byte[]> ReadBoundedBodyAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using var input = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var output = new MemoryStream();
        var buffer = new byte[81920];
        for (;;)
        {
            var count = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (count == 0) break;
            if (output.Length + count > MaxResponseBytes) throw new InvalidDataException("response body exceeds 1 MiB limit");
            await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
        }
        return output.ToArray();
    }
}
