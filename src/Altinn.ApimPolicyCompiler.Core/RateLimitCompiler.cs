using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Altinn.ApimPolicyCompiler.Core;

public static class RateLimitCompiler
{
    private static readonly HashSet<string> ValidMethods = new(StringComparer.Ordinal)
    {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"
    };

    private static readonly HashSet<string> ValidPathModes = new(StringComparer.Ordinal)
    {
        "any", "exact", "prefix"
    };

    private static readonly HashSet<string> ValidKeyModes = new(StringComparer.Ordinal)
    {
        "client-id", "client-id-ip", "client-id-claim"
    };

    public static CompilationResult CompileJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        RateLimitConfig? config;
        try
        {
            config = JsonSerializer.Deserialize(json, RateLimitJsonContext.Default.RateLimitConfig);
        }
        catch (JsonException ex)
        {
            return Fail(new Diagnostic(DiagnosticSeverity.Error, "APIMRL0001", $"Invalid JSON: {ex.Message}"));
        }

        if (config is null)
        {
            return Fail(new Diagnostic(DiagnosticSeverity.Error, "APIMRL0001", "Invalid JSON: document must be an object."));
        }

        var diagnostics = Validate(config);
        if (diagnostics.Any(static x => x.Severity == DiagnosticSeverity.Error))
        {
            return new CompilationResult(false, null, null, diagnostics);
        }

        var xml = GenerateXml(config);
        try
        {
            _ = XDocument.Parse(xml, LoadOptions.PreserveWhitespace);
        }
        catch (XmlException ex)
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL9001", $"Generated XML is not well-formed: {ex.Message}"));
            return new CompilationResult(false, null, null, diagnostics);
        }

        return new CompilationResult(true, xml, ComputeSha256(xml), diagnostics);
    }

    public static string ComputeSha256(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static CompilationResult Fail(Diagnostic diagnostic)
    {
        return new CompilationResult(false, null, null, [diagnostic]);
    }

    private static List<Diagnostic> Validate(RateLimitConfig config)
    {
        var diagnostics = new List<Diagnostic>();

        AddUnknownProperties(diagnostics, config.ExtensionData, "$");

        if (config.Version != 1)
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1001", "Only version 1 is supported.", "version"));
        }

        if (!IsSafeName(config.Scope))
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1002", "Scope is required and may only contain letters, digits, '-' and '_'.", "scope"));
        }

        if (config.Rules is null)
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1003", "Rules must be present.", "rules"));
            return diagnostics;
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < config.Rules.Count; i++)
        {
            var rule = config.Rules[i];
            var target = $"rules[{i}]";

            AddUnknownProperties(diagnostics, rule.ExtensionData, target);

            if (!IsSafeName(rule.Id))
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1101", "Rule id is required and may only contain letters, digits, '-' and '_'.", $"{target}.id"));
            }
            else if (!ids.Add(rule.Id!))
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1102", $"Duplicate rule id '{rule.Id}'.", $"{target}.id"));
            }

            ValidateMethods(diagnostics, rule, target);
            ValidateMode(diagnostics, ValidPathModes, rule.PathMode, "pathMode", "APIMRL1104", target);
            ValidateMode(diagnostics, ValidKeyModes, rule.KeyMode, "keyMode", "APIMRL1105", target);

            if ((rule.PathMode == "exact" || rule.PathMode == "prefix") && string.IsNullOrWhiteSpace(rule.Path))
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1106", "Path is required when pathMode is exact or prefix.", $"{target}.path"));
            }

            if (rule.KeyMode == "client-id-claim" && string.IsNullOrWhiteSpace(rule.KeyClaimName))
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1107", "keyClaimName is required when keyMode is client-id-claim.", $"{target}.keyClaimName"));
            }

            if (rule.Calls <= 0)
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1108", "calls must be greater than 0.", $"{target}.calls"));
            }

            if (rule.RenewalPeriod is <= 0 or > 300)
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1109", "renewalPeriod must be between 1 and 300 seconds.", $"{target}.renewalPeriod"));
            }

            if (rule is { Enabled: true, Calls: >= 10000 })
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Warning, "APIMRL2004", "Rule has a very high call limit.", $"{target}.calls"));
            }
        }

        var enabledRules = config.Rules.Where(static x => x.Enabled).ToArray();
        if (enabledRules.Length > 10)
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Warning, "APIMRL2003", "Scope contains many enabled rules.", "rules"));
        }

        return diagnostics;
    }

    private static void AddUnknownProperties(List<Diagnostic> diagnostics, Dictionary<string, JsonElement>? extensionData, string target)
    {
        if (extensionData is null)
        {
            return;
        }

        foreach (var property in extensionData.Keys.Order(StringComparer.Ordinal))
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1000", $"Unknown property '{property}'.", target));
        }
    }

    private static void ValidateMethods(List<Diagnostic> diagnostics, RateLimitRule rule, string target)
    {
        if (rule.Methods is null || rule.Methods.Count == 0)
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1103", "methods must contain '*' or at least one supported HTTP method.", $"{target}.methods"));
            return;
        }

        if (rule.Methods.Contains("*", StringComparer.Ordinal) && rule.Methods.Count > 1)
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1103", "methods cannot combine '*' with explicit HTTP methods.", $"{target}.methods"));
            return;
        }

        foreach (var method in rule.Methods)
        {
            if (method == "*")
            {
                continue;
            }

            if (!ValidMethods.Contains(method))
            {
                diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, "APIMRL1103", $"Unsupported HTTP method '{method}'.", $"{target}.methods"));
            }
        }
    }

    private static void ValidateMode(List<Diagnostic> diagnostics, HashSet<string> validModes, string? value, string property, string code, string target)
    {
        if (value is null || !validModes.Contains(value))
        {
            diagnostics.Add(new Diagnostic(DiagnosticSeverity.Error, code, $"Unsupported {property} '{value ?? "<missing>"}'.", $"{target}.{property}"));
        }
    }

    private static bool IsSafeName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        foreach (var c in value)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')
            {
                return false;
            }
        }

        return true;
    }

    private static string GenerateXml(RateLimitConfig config)
    {
        var fragment = new XElement("fragment");
        if (!config.Enabled)
        {
            return WriteDocument(fragment);
        }

        fragment.Add(CreatePreamble());

        foreach (var rule in config.Rules!.Where(static x => x.Enabled).OrderBy(static x => x.Id, StringComparer.Ordinal))
        {
            fragment.Add(CreateRuleChoose(config.Scope!, rule));
        }

        return WriteDocument(fragment);
    }

    private static XElement CreatePreamble()
    {
        var missingClientId = NormalizePolicyExpression(
            // language=C#
            """
            @(
                !(context.Variables.ContainsKey("oauthClientId")
                    && !string.IsNullOrEmpty((string)context.Variables["oauthClientId"]))
            )
            """);

        var resolveClientId = NormalizePolicyExpression(
            // language=C#
            """
            @{
                var authorization = context.Request.Headers.GetValueOrDefault("Authorization", "");

                if (!string.IsNullOrEmpty(authorization)
                    && authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    var jwt = authorization.Substring(7).AsJwt();

                    if (jwt != null && jwt.Claims.ContainsKey("client_id"))
                    {
                        return jwt.Claims.GetValueOrDefault("client_id", "");
                    }
                }

                return "";
            }
            """);

        return new XElement(
            "choose",
            new XElement(
                "when",
                new XAttribute("condition", missingClientId),
                new XElement(
                    "set-variable",
                    new XAttribute("name", "oauthClientId"),
                    new XAttribute("value", resolveClientId))));
    }

    private static XElement CreateRuleChoose(string scope, RateLimitRule rule)
    {
        var condition = NormalizePolicyExpression(
            // language=C#
            $$"""
            @(
                !string.IsNullOrEmpty((string)context.Variables["oauthClientId"])
                && {{BuildMatchExpression(rule)}}
            )
            """);

        return new XElement(
            "choose",
            new XElement(
                "when",
                new XAttribute("condition", condition),
                new XElement(
                    "rate-limit-by-key",
                    new XAttribute("calls", rule.Calls.ToString(CultureInfo.InvariantCulture)),
                    new XAttribute("renewal-period", rule.RenewalPeriod.ToString(CultureInfo.InvariantCulture)),
                    new XAttribute("counter-key", BuildCounterKeyExpression(scope, rule)),
                    new XAttribute("remaining-calls-header-name", $"X-RateLimit-Remaining-{scope}-{rule.Id}"),
                    new XAttribute("total-calls-header-name", $"X-RateLimit-Limit-{scope}-{rule.Id}"),
                    new XAttribute("retry-after-header-name", "Retry-After"))));
    }

    private static string BuildMatchExpression(RateLimitRule rule)
    {
        var methodExpression = rule.Methods is ["*"]
            ? "true"
            : NormalizePolicyExpression(
                $$"""
                (
                    {{string.Join(
                        " || ",
                        rule.Methods!
                            .Order(StringComparer.Ordinal)
                            .Select(static x => $"context.Request.Method == {QuotePolicyString(x)}"))}}
                )
                """);

        var pathExpression = rule.PathMode switch
        {
            "any" => "true",
            "exact" => NormalizePolicyExpression(
                $$"""
                context.Request.Url.Path == {{QuotePolicyString(rule.Path!)}}
                """),
            "prefix" => NormalizePolicyExpression(
                $$"""
                context.Request.Url.Path.StartsWith(
                    {{QuotePolicyString(rule.Path!)}},
                    StringComparison.Ordinal
                )
                """),
            _ => "false"
        };

        return NormalizePolicyExpression(
            $$"""
            (
                {{methodExpression}}
                && {{pathExpression}}
            )
            """);
    }

    private static string BuildCounterKeyExpression(string scope, RateLimitRule rule)
    {
        var prefix = $"{scope}:{rule.Id}:{rule.KeyMode}:";
        return rule.KeyMode switch
        {
            "client-id" => BuildClientIdCounterKey(prefix),
            "client-id-ip" => NormalizePolicyExpression(
                $$"""
                @(
                    {{QuotePolicyString(prefix)}}
                    + (string)context.Variables["oauthClientId"]
                    + ":"
                    + context.Request.IpAddress
                )
                """),
            "client-id-claim" => BuildClientIdCounterKey($"{prefix}{rule.KeyClaimName!}:"),
            _ => BuildClientIdCounterKey(prefix)
        };
    }

    private static string BuildClientIdCounterKey(string prefix)
    {
        return NormalizePolicyExpression(
            $$"""
            @(
                {{QuotePolicyString(prefix)}}
                + (string)context.Variables["oauthClientId"]
            )
            """);
    }

    private static string NormalizePolicyExpression(string expression)
    {
        return string.Join(
            " ",
            expression
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Select(static x => x.Trim()))
            .Replace("@( ", "@(", StringComparison.Ordinal)
            .Replace("( ", "(", StringComparison.Ordinal)
            .Replace(" )", ")", StringComparison.Ordinal);
    }

    private static string QuotePolicyString(string value)
    {
        return "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
    }

    private static string WriteDocument(XElement fragment)
    {
        var settings = new XmlWriterSettings
        {
            OmitXmlDeclaration = true,
            Encoding = new UTF8Encoding(false),
            Indent = true,
            NewLineChars = "\n",
            NewLineHandling = NewLineHandling.Replace
        };

        using var stream = new MemoryStream();
        using (var writer = XmlWriter.Create(stream, settings))
        {
            fragment.Save(writer);
        }

        return Encoding.UTF8.GetString(stream.ToArray()) + "\n";
    }
}
