using System.Diagnostics;
using System.Text;
using System.Text.Json;

var iterations = 2_000_000;
for (var i = 0; i < args.Length - 1; i++)
{
    if (args[i] == "--iterations" && int.TryParse(args[i + 1], out var parsed) && parsed > 0)
    {
        iterations = parsed;
    }
}

var payloads = new[]
{
    """{"iss":"https://issuer.example","sub":"user","aud":"api","client_id":"partner-a","scope":"orders:read orders:write","iat":1710000000,"exp":1710003600}""",
    """{"iss":"https://issuer.example","sub":"user","aud":"api","azp":"other","client_id":"partner-b","scope":"profile","iat":1710000000,"exp":1710003600}""",
    """{"iss":"https://issuer.example","sub":"user","aud":"api","scope":"profile","iat":1710000000,"exp":1710003600}""",
    """{"iss":"https://issuer.example","sub":"user","aud":"api","client_id" : "partner-c","scope":"profile","iat":1710000000,"exp":1710003600}""",
};

var authorizations = payloads
    .Select(static x => "Bearer " + ToJwt(x))
    .ToArray();

var variants = new (string Name, Func<string, string> Extract)[]
{
    ("JSON parse baseline (AsJwt-style)", ExtractWithJsonDocument),
    ("string replace + string scan", ExtractWithReplaceAndStringScan),
    ("string replace + UTF8 byte scan", ExtractWithReplaceAndUtf8Scan),
    ("direct payload substring + UTF8 byte scan", ExtractWithDirectPayloadSubstringAndUtf8Scan),
    ("direct payload substring + ASCII byte scan", ExtractWithDirectPayloadSubstringAndAsciiScan),
    ("direct payload substring + Encoding.ASCII", ExtractWithDirectPayloadSubstringAndEncodingAsciiScan),
    ("conditional replace + UTF8 byte scan", ExtractWithConditionalReplaceAndUtf8Scan),
    ("stream base64url state machine", ExtractWithStreamingBase64UrlStateMachine),
    ("string replace + Array.IndexOf byte scan", ExtractWithReplaceAndArrayIndexUtf8Scan),
    ("char[] normalize + string scan", ExtractWithCharArrayAndStringScan),
    ("char[] normalize + UTF8 byte scan", ExtractWithCharArrayAndUtf8Scan),
};

Console.WriteLine($"Iterations per variant: {iterations:N0}");
Console.WriteLine($"Payloads: {authorizations.Length}");
Console.WriteLine();

foreach (var variant in variants)
{
    for (var warmup = 0; warmup < 20_000; warmup++)
    {
        _ = variant.Extract(authorizations[warmup % authorizations.Length]);
    }
}

foreach (var variant in variants)
{
    GC.Collect();
    GC.WaitForPendingFinalizers();
    GC.Collect();

    var beforeBytes = GC.GetAllocatedBytesForCurrentThread();
    var sw = Stopwatch.StartNew();
    var checksum = 0;

    for (var i = 0; i < iterations; i++)
    {
        checksum += variant.Extract(authorizations[i % authorizations.Length]).Length;
    }

    sw.Stop();
    var allocated = GC.GetAllocatedBytesForCurrentThread() - beforeBytes;
    var nsPerOp = sw.Elapsed.TotalMilliseconds * 1_000_000 / iterations;
    var bytesPerOp = (double)allocated / iterations;

    Console.WriteLine($"{variant.Name,-34} {nsPerOp,9:N1} ns/op {bytesPerOp,9:N1} B/op checksum={checksum}");
}

static string ToJwt(string json)
{
    return Base64Url("""{"alg":"none","typ":"JWT"}""") + "." + Base64Url(json) + ".";
}

static string Base64Url(string value)
{
    return Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');
}

static string ExtractWithJsonDocument(string authorization)
{
    if (string.IsNullOrEmpty(authorization)
        || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        || authorization.Length <= 7)
    {
        return "";
    }

    var token = authorization.Substring(7);
    var firstDot = token.IndexOf('.');
    if (firstDot < 0)
    {
        return "";
    }

    var secondDot = token.IndexOf('.', firstDot + 1);
    if (secondDot <= firstDot + 1)
    {
        return "";
    }

    var payload = token.Substring(firstDot + 1, secondDot - firstDot - 1)
        .Replace('-', '+')
        .Replace('_', '/');

    var remainder = payload.Length % 4;
    if (remainder == 2)
    {
        payload += "==";
    }
    else if (remainder == 3)
    {
        payload += "=";
    }

    try
    {
        using var document = JsonDocument.Parse(Convert.FromBase64String(payload));
        return document.RootElement.TryGetProperty("client_id", out var clientId) && clientId.ValueKind == JsonValueKind.String
            ? clientId.GetString() ?? ""
            : "";
    }
    catch
    {
        return "";
    }
}

static string ExtractWithReplaceAndStringScan(string authorization)
{
    var bytes = DecodePayloadWithReplace(authorization);
    if (bytes.Length == 0)
    {
        return "";
    }

    var json = Encoding.UTF8.GetString(bytes);
    return FindClientIdInString(json);
}

static string ExtractWithReplaceAndUtf8Scan(string authorization)
{
    var bytes = DecodePayloadWithReplace(authorization);
    return bytes.Length == 0 ? "" : FindClientIdInUtf8(bytes);
}

static string ExtractWithReplaceAndArrayIndexUtf8Scan(string authorization)
{
    var bytes = DecodePayloadWithReplace(authorization);
    return bytes.Length == 0 ? "" : FindClientIdInUtf8WithArrayIndex(bytes);
}

static string ExtractWithDirectPayloadSubstringAndUtf8Scan(string authorization)
{
    var bytes = DecodePayloadWithDirectPayloadSubstring(authorization);
    return bytes.Length == 0 ? "" : FindClientIdInUtf8(bytes);
}

static string ExtractWithDirectPayloadSubstringAndAsciiScan(string authorization)
{
    var bytes = DecodePayloadWithDirectPayloadSubstring(authorization);
    return bytes.Length == 0 ? "" : FindClientIdInAscii(bytes);
}

static string ExtractWithDirectPayloadSubstringAndEncodingAsciiScan(string authorization)
{
    var bytes = DecodePayloadWithDirectPayloadSubstring(authorization);
    return bytes.Length == 0 ? "" : FindClientIdInEncodingAscii(bytes);
}

static string ExtractWithConditionalReplaceAndUtf8Scan(string authorization)
{
    var bytes = DecodePayloadWithConditionalReplace(authorization);
    return bytes.Length == 0 ? "" : FindClientIdInUtf8(bytes);
}

static string ExtractWithStreamingBase64UrlStateMachine(string authorization)
{
    if (string.IsNullOrEmpty(authorization)
        || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        || authorization.Length <= 7)
    {
        return "";
    }

    var firstDot = authorization.IndexOf('.', 7);
    if (firstDot < 0)
    {
        return "";
    }

    var secondDot = authorization.IndexOf('.', firstDot + 1);
    if (secondDot <= firstDot + 1)
    {
        return "";
    }

    var buffer = 0;
    var bits = 0;
    var match = 0;
    var state = 0;
    var value = Array.Empty<char>();
    var valueLength = 0;

    for (var i = firstDot + 1; i < secondDot; i++)
    {
        var c = authorization[i];
        int decoded;

        if (c >= 'A' && c <= 'Z')
        {
            decoded = c - 'A';
        }
        else if (c >= 'a' && c <= 'z')
        {
            decoded = c - 'a' + 26;
        }
        else if (c >= '0' && c <= '9')
        {
            decoded = c - '0' + 52;
        }
        else if (c == '-' || c == '+')
        {
            decoded = 62;
        }
        else if (c == '_' || c == '/')
        {
            decoded = 63;
        }
        else if (c == '=')
        {
            break;
        }
        else
        {
            return "";
        }

        buffer = (buffer << 6) | decoded;
        bits += 6;

        if (bits < 8)
        {
            continue;
        }

        bits -= 8;
        var b = (byte)((buffer >> bits) & 0xff);

        if (state == 0)
        {
            if ((match == 0 && b == (byte)'"')
                || (match == 1 && b == (byte)'c')
                || (match == 2 && b == (byte)'l')
                || (match == 3 && b == (byte)'i')
                || (match == 4 && b == (byte)'e')
                || (match == 5 && b == (byte)'n')
                || (match == 6 && b == (byte)'t')
                || (match == 7 && b == (byte)'_')
                || (match == 8 && b == (byte)'i')
                || (match == 9 && b == (byte)'d')
                || (match == 10 && b == (byte)'"'))
            {
                match++;
                if (match == 11)
                {
                    state = 1;
                    match = 0;
                }

                continue;
            }

            match = b == (byte)'"' ? 1 : 0;
            continue;
        }

        if (state == 1)
        {
            if (b == (byte)' ' || b == (byte)'\t' || b == (byte)'\r' || b == (byte)'\n')
            {
                continue;
            }

            if (b != (byte)':')
            {
                state = 0;
                match = b == (byte)'"' ? 1 : 0;
                continue;
            }

            state = 2;
            continue;
        }

        if (state == 2)
        {
            if (b == (byte)' ' || b == (byte)'\t' || b == (byte)'\r' || b == (byte)'\n')
            {
                continue;
            }

            if (b != (byte)'"')
            {
                state = 0;
                match = b == (byte)'"' ? 1 : 0;
                continue;
            }

            value = new char[64];
            valueLength = 0;
            state = 3;
            continue;
        }

        if (b == (byte)'"')
        {
            return valueLength > 0 ? new string(value, 0, valueLength) : "";
        }

        if (valueLength == value.Length)
        {
            Array.Resize(ref value, value.Length * 2);
        }

        value[valueLength++] = (char)b;
    }

    return "";
}

static byte[] DecodePayloadWithReplace(string authorization)
{
    if (string.IsNullOrEmpty(authorization)
        || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        || authorization.Length <= 7)
    {
        return [];
    }

    var token = authorization.Substring(7);
    var firstDot = token.IndexOf('.');
    if (firstDot < 0)
    {
        return [];
    }

    var secondDot = token.IndexOf('.', firstDot + 1);
    if (secondDot <= firstDot + 1)
    {
        return [];
    }

    var payload = token.Substring(firstDot + 1, secondDot - firstDot - 1)
        .Replace('-', '+')
        .Replace('_', '/');

    var remainder = payload.Length % 4;
    if (remainder == 1)
    {
        return [];
    }

    if (remainder == 2)
    {
        payload += "==";
    }
    else if (remainder == 3)
    {
        payload += "=";
    }

    try
    {
        return Convert.FromBase64String(payload);
    }
    catch
    {
        return [];
    }
}

static byte[] DecodePayloadWithDirectPayloadSubstring(string authorization)
{
    if (string.IsNullOrEmpty(authorization)
        || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        || authorization.Length <= 7)
    {
        return [];
    }

    var firstDot = authorization.IndexOf('.', 7);
    if (firstDot < 0)
    {
        return [];
    }

    var secondDot = authorization.IndexOf('.', firstDot + 1);
    if (secondDot <= firstDot + 1)
    {
        return [];
    }

    var payload = authorization.Substring(firstDot + 1, secondDot - firstDot - 1)
        .Replace('-', '+')
        .Replace('_', '/');

    var remainder = payload.Length % 4;
    if (remainder == 1)
    {
        return [];
    }

    if (remainder == 2)
    {
        payload += "==";
    }
    else if (remainder == 3)
    {
        payload += "=";
    }

    try
    {
        return Convert.FromBase64String(payload);
    }
    catch
    {
        return [];
    }
}

static byte[] DecodePayloadWithConditionalReplace(string authorization)
{
    if (string.IsNullOrEmpty(authorization)
        || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        || authorization.Length <= 7)
    {
        return [];
    }

    var firstDot = authorization.IndexOf('.', 7);
    if (firstDot < 0)
    {
        return [];
    }

    var secondDot = authorization.IndexOf('.', firstDot + 1);
    if (secondDot <= firstDot + 1)
    {
        return [];
    }

    var payload = authorization.Substring(firstDot + 1, secondDot - firstDot - 1);
    if (payload.IndexOf('-') >= 0)
    {
        payload = payload.Replace('-', '+');
    }

    if (payload.IndexOf('_') >= 0)
    {
        payload = payload.Replace('_', '/');
    }

    var remainder = payload.Length % 4;
    if (remainder == 1)
    {
        return [];
    }

    if (remainder == 2)
    {
        payload += "==";
    }
    else if (remainder == 3)
    {
        payload += "=";
    }

    try
    {
        return Convert.FromBase64String(payload);
    }
    catch
    {
        return [];
    }
}

static string ExtractWithCharArrayAndStringScan(string authorization)
{
    var bytes = DecodePayload(authorization);
    if (bytes.Length == 0)
    {
        return "";
    }

    var json = Encoding.UTF8.GetString(bytes);
    return FindClientIdInString(json);
}

static string ExtractWithCharArrayAndUtf8Scan(string authorization)
{
    var bytes = DecodePayload(authorization);
    return bytes.Length == 0 ? "" : FindClientIdInUtf8(bytes);
}

static byte[] DecodePayload(string authorization)
{
    if (string.IsNullOrEmpty(authorization)
        || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        || authorization.Length <= 7)
    {
        return [];
    }

    var firstDot = authorization.IndexOf('.', 7);
    if (firstDot < 0)
    {
        return [];
    }

    var secondDot = authorization.IndexOf('.', firstDot + 1);
    if (secondDot <= firstDot + 1)
    {
        return [];
    }

    var payloadLength = secondDot - firstDot - 1;
    var remainder = payloadLength % 4;
    if (remainder == 1)
    {
        return [];
    }

    var padding = remainder == 2 ? 2 : remainder == 3 ? 1 : 0;
    var base64 = new char[payloadLength + padding];
    var payloadStart = firstDot + 1;

    for (var i = 0; i < payloadLength; i++)
    {
        var c = authorization[payloadStart + i];
        base64[i] = c == '-' ? '+' : c == '_' ? '/' : c;
    }

    for (var i = 0; i < padding; i++)
    {
        base64[payloadLength + i] = '=';
    }

    try
    {
        return Convert.FromBase64CharArray(base64, 0, base64.Length);
    }
    catch
    {
        return [];
    }
}

static string FindClientIdInString(string json)
{
    var name = "\"client_id\"";
    var index = json.IndexOf(name, StringComparison.Ordinal);

    while (index >= 0)
    {
        var cursor = index + name.Length;
        while (cursor < json.Length
            && (json[cursor] == ' ' || json[cursor] == '\t' || json[cursor] == '\r' || json[cursor] == '\n'))
        {
            cursor++;
        }

        if (cursor >= json.Length || json[cursor] != ':')
        {
            index = json.IndexOf(name, cursor, StringComparison.Ordinal);
            continue;
        }

        cursor++;
        while (cursor < json.Length
            && (json[cursor] == ' ' || json[cursor] == '\t' || json[cursor] == '\r' || json[cursor] == '\n'))
        {
            cursor++;
        }

        if (cursor >= json.Length || json[cursor] != '"')
        {
            index = json.IndexOf(name, cursor, StringComparison.Ordinal);
            continue;
        }

        var start = cursor + 1;
        var end = json.IndexOf('"', start);
        return end > start ? json.Substring(start, end - start) : "";
    }

    return "";
}

static string FindClientIdInUtf8(byte[] json)
{
    for (var i = 0; i <= json.Length - 11; i++)
    {
        if (json[i] != (byte)'"'
            || json[i + 1] != (byte)'c'
            || json[i + 2] != (byte)'l'
            || json[i + 3] != (byte)'i'
            || json[i + 4] != (byte)'e'
            || json[i + 5] != (byte)'n'
            || json[i + 6] != (byte)'t'
            || json[i + 7] != (byte)'_'
            || json[i + 8] != (byte)'i'
            || json[i + 9] != (byte)'d'
            || json[i + 10] != (byte)'"')
        {
            continue;
        }

        var cursor = i + 11;
        while (cursor < json.Length
            && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t' || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'))
        {
            cursor++;
        }

        if (cursor >= json.Length || json[cursor] != (byte)':')
        {
            continue;
        }

        cursor++;
        while (cursor < json.Length
            && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t' || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'))
        {
            cursor++;
        }

        if (cursor >= json.Length || json[cursor] != (byte)'"')
        {
            continue;
        }

        var start = cursor + 1;
        var end = start;
        while (end < json.Length && json[end] != (byte)'"')
        {
            end++;
        }

        return end > start ? Encoding.UTF8.GetString(json, start, end - start) : "";
    }

    return "";
}

static string FindClientIdInAscii(byte[] json)
{
    for (var i = 0; i <= json.Length - 11; i++)
    {
        if (json[i] != (byte)'"'
            || json[i + 1] != (byte)'c'
            || json[i + 2] != (byte)'l'
            || json[i + 3] != (byte)'i'
            || json[i + 4] != (byte)'e'
            || json[i + 5] != (byte)'n'
            || json[i + 6] != (byte)'t'
            || json[i + 7] != (byte)'_'
            || json[i + 8] != (byte)'i'
            || json[i + 9] != (byte)'d'
            || json[i + 10] != (byte)'"')
        {
            continue;
        }

        var cursor = i + 11;
        while (cursor < json.Length
            && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t' || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'))
        {
            cursor++;
        }

        if (cursor >= json.Length || json[cursor] != (byte)':')
        {
            continue;
        }

        cursor++;
        while (cursor < json.Length
            && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t' || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'))
        {
            cursor++;
        }

        if (cursor >= json.Length || json[cursor] != (byte)'"')
        {
            continue;
        }

        var start = cursor + 1;
        var end = start;
        while (end < json.Length && json[end] != (byte)'"')
        {
            end++;
        }

        if (end <= start)
        {
            return "";
        }

        var chars = new char[end - start];
        for (var j = 0; j < chars.Length; j++)
        {
            chars[j] = (char)json[start + j];
        }

        return new string(chars);
    }

    return "";
}

static string FindClientIdInEncodingAscii(byte[] json)
{
    for (var i = 0; i <= json.Length - 11; i++)
    {
        if (json[i] != (byte)'"'
            || json[i + 1] != (byte)'c'
            || json[i + 2] != (byte)'l'
            || json[i + 3] != (byte)'i'
            || json[i + 4] != (byte)'e'
            || json[i + 5] != (byte)'n'
            || json[i + 6] != (byte)'t'
            || json[i + 7] != (byte)'_'
            || json[i + 8] != (byte)'i'
            || json[i + 9] != (byte)'d'
            || json[i + 10] != (byte)'"')
        {
            continue;
        }

        var cursor = i + 11;
        while (cursor < json.Length
            && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t' || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'))
        {
            cursor++;
        }

        if (cursor >= json.Length || json[cursor] != (byte)':')
        {
            continue;
        }

        cursor++;
        while (cursor < json.Length
            && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t' || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'))
        {
            cursor++;
        }

        if (cursor >= json.Length || json[cursor] != (byte)'"')
        {
            continue;
        }

        var start = cursor + 1;
        var end = start;
        while (end < json.Length && json[end] != (byte)'"')
        {
            end++;
        }

        return end > start ? Encoding.ASCII.GetString(json, start, end - start) : "";
    }

    return "";
}

static string FindClientIdInUtf8WithArrayIndex(byte[] json)
{
    var i = 0;
    while (i <= json.Length - 11)
    {
        i = Array.IndexOf(json, (byte)'"', i);
        if (i < 0 || i > json.Length - 11)
        {
            return "";
        }

        if (json[i + 1] != (byte)'c'
            || json[i + 2] != (byte)'l'
            || json[i + 3] != (byte)'i'
            || json[i + 4] != (byte)'e'
            || json[i + 5] != (byte)'n'
            || json[i + 6] != (byte)'t'
            || json[i + 7] != (byte)'_'
            || json[i + 8] != (byte)'i'
            || json[i + 9] != (byte)'d'
            || json[i + 10] != (byte)'"')
        {
            i++;
            continue;
        }

        var cursor = i + 11;
        while (cursor < json.Length
            && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t' || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'))
        {
            cursor++;
        }

        if (cursor >= json.Length || json[cursor] != (byte)':')
        {
            i++;
            continue;
        }

        cursor++;
        while (cursor < json.Length
            && (json[cursor] == (byte)' ' || json[cursor] == (byte)'\t' || json[cursor] == (byte)'\r' || json[cursor] == (byte)'\n'))
        {
            cursor++;
        }

        if (cursor >= json.Length || json[cursor] != (byte)'"')
        {
            i++;
            continue;
        }

        var start = cursor + 1;
        var end = Array.IndexOf(json, (byte)'"', start);
        return end > start ? Encoding.UTF8.GetString(json, start, end - start) : "";
    }

    return "";
}
