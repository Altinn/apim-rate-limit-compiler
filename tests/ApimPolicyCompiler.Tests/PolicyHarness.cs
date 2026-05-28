using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace ApimPolicyCompiler.Tests;

public sealed class PolicyHarness
{
    private readonly PolicyExpressionCompiler _compiler = new();
    private readonly Dictionary<string, IPolicyExpressionEvaluator> _evaluators = new(StringComparer.Ordinal);

    public PolicyRunResult Run(string xml, FakeContext context)
    {
        var document = XDocument.Parse(xml);
        foreach (var element in document.Root!.Elements())
        {
            Execute(element, context);
        }

        return new PolicyRunResult(new Dictionary<string, object?>(context.Variables, StringComparer.Ordinal), context.AppliedRateLimits.ToArray());
    }

    private void Execute(XElement element, FakeContext context)
    {
        switch (element.Name.LocalName)
        {
            case "choose":
                ExecuteChoose(element, context);
                break;
            case "set-variable":
                ExecuteSetVariable(element, context);
                break;
            case "rate-limit-by-key":
                ExecuteRateLimit(element, context);
                break;
        }
    }

    private void ExecuteChoose(XElement choose, FakeContext context)
    {
        foreach (var when in choose.Elements("when"))
        {
            if (Convert.ToBoolean(Evaluate(when.Attribute("condition")!.Value, "when", "condition", context)))
            {
                foreach (var child in when.Elements())
                {
                    Execute(child, context);
                }

                return;
            }
        }

        var otherwise = choose.Element("otherwise");
        if (otherwise is null)
        {
            return;
        }

        foreach (var child in otherwise.Elements())
        {
            Execute(child, context);
        }
    }

    private void ExecuteSetVariable(XElement setVariable, FakeContext context)
    {
        var name = setVariable.Attribute("name")!.Value;
        var value = Evaluate(setVariable.Attribute("value")!.Value, "set-variable", "value", context);
        context.Variables[name] = value ?? "";
    }

    private void ExecuteRateLimit(XElement rateLimit, FakeContext context)
    {
        context.AppliedRateLimits.Add(new AppliedRateLimit(
            (string)Evaluate(rateLimit.Attribute("counter-key")!.Value, "rate-limit-by-key", "counter-key", context)!));
    }

    private object? Evaluate(string text, string elementName, string attributeName, FakeContext context)
    {
        var key = elementName + "/" + attributeName + ":" + text;
        if (!_evaluators.TryGetValue(key, out var evaluator))
        {
            evaluator = _compiler.Compile(new PolicyExpression(elementName, attributeName, text, $"{elementName}/@{attributeName}"));
            _evaluators.Add(key, evaluator);
        }

        return evaluator.Evaluate(context);
    }
}

public sealed record PolicyRunResult(
    Dictionary<string, object?> Variables,
    IReadOnlyList<AppliedRateLimit> AppliedRateLimits);

// ReSharper disable once NotAccessedPositionalProperty.Global
public sealed record AppliedRateLimit(string CounterKey);

public sealed class FakeContext
{
    public FakeRequest Request { get; } = new();

    public Dictionary<string, object?> Variables { get; } = new(StringComparer.Ordinal);

    public List<AppliedRateLimit> AppliedRateLimits { get; } = [];
}

public sealed class FakeRequest
{
    public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string Method { get; set; } = "GET";

    public FakeUrl Url { get; } = new();

    public string IpAddress { get; set; } = "127.0.0.1";
}

public sealed class FakeUrl
{
    public string Path { get; set; } = "/";
}

public sealed class FakeJwt
{
    public Dictionary<string, string> Claims { get; } = new(StringComparer.Ordinal);
}


// ReSharper disable once UnusedType.Global
// Used by Roslyn-compiled generated policy expressions that call token.AsJwt().
public static class FakeApimJwtExtensions
{
    // ReSharper disable once UnusedMember.Global
    public static FakeJwt? AsJwt(this string token)
    {
        var segments = token.Split('.');
        if (segments.Length < 2)
        {
            return null;
        }

        try
        {
            var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(DecodeBase64Url(segments[1]));
            if (payload is null)
            {
                return null;
            }

            var jwt = new FakeJwt();
            foreach (var (name, value) in payload)
            {
                jwt.Claims[name] = value.ValueKind == JsonValueKind.String
                    ? value.GetString() ?? ""
                    : value.ToString();
            }

            return jwt;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string DecodeBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + ((4 - padded.Length % 4) % 4), '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(padded));
    }
}

public static class JwtFixture
{
    public static string CreateAuthorizationHeader(params (string Name, string Value)[] claims)
    {
        return "Bearer " + CreateUnsignedJwt(claims);
    }

    private static string CreateUnsignedJwt(params (string Name, string Value)[] claims)
    {
        var payload = claims.ToDictionary(static x => x.Name, static x => x.Value, StringComparer.Ordinal);
        return Base64Url("""{"alg":"none","typ":"JWT"}""")
            + "."
            + Base64Url(JsonSerializer.Serialize(payload))
            + ".";
    }

    private static string Base64Url(string value)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
