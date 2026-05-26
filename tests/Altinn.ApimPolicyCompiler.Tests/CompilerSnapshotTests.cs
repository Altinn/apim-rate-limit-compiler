using System.Xml.Linq;
using Altinn.ApimPolicyCompiler.Cli;
using Altinn.ApimPolicyCompiler.Core;

namespace Altinn.ApimPolicyCompiler.Tests;

public sealed class CompilerSnapshotTests
{
    private static readonly string FixtureRoot = Path.Combine(AppContext.BaseDirectory, "Fixtures");

    [Theory]
    [MemberData(nameof(ValidFixtures))]
    public void Valid_fixtures_match_xml_snapshots(string fixture)
    {
        var json = File.ReadAllText(fixture);
        var result = RateLimitCompiler.CompileJson(json);

        Assert.True(result.Success, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.Xml);
        Assert.NotNull(result.Sha256);
        Assert.Equal(File.ReadAllText(Path.ChangeExtension(fixture, ".fragment.xml.snap")), result.Xml);
        XDocument.Parse(result.Xml);
        Assert.Equal(result.Sha256, RateLimitCompiler.ComputeSha256(result.Xml));
    }

    [Theory]
    [MemberData(nameof(InvalidFixtures))]
    public void Invalid_fixtures_match_diagnostic_snapshots(string fixture)
    {
        var json = File.ReadAllText(fixture);
        var result = RateLimitCompiler.CompileJson(json);

        Assert.False(result.Success);
        Assert.Null(result.Xml);
        Assert.Equal(File.ReadAllText(Path.ChangeExtension(fixture, ".diagnostics.snap")), FormatDiagnostics(result.Diagnostics));
    }

    [Fact]
    public void Output_is_deterministic_across_repeated_runs()
    {
        var json = File.ReadAllText(Path.Combine(FixtureRoot, "valid", "multiple-rules.json"));

        var first = RateLimitCompiler.CompileJson(json);
        var second = RateLimitCompiler.CompileJson(json);

        Assert.True(first.Success);
        Assert.Equal(first.Xml, second.Xml);
        Assert.Equal(first.Sha256, second.Sha256);
    }

    [Fact]
    public void Client_counter_keys_read_oauth_client_id_variable()
    {
        var json = File.ReadAllText(Path.Combine(FixtureRoot, "valid", "key-modes.json"));

        var result = RateLimitCompiler.CompileJson(json);

        Assert.True(result.Success);
        var document = XDocument.Parse(result.Xml!);
        var counterKeys = document.Descendants("rate-limit-by-key")
            .Select(static x => x.Attribute("counter-key")?.Value)
            .ToArray();
        Assert.NotEmpty(counterKeys);
        Assert.All(counterKeys, static x => Assert.Contains("context.Variables[\"oauthClientId\"]", x));
    }

    [Fact]
    public void Rate_limit_headers_are_omitted_by_default_and_emitted_when_requested()
    {
        var json = File.ReadAllText(Path.Combine(FixtureRoot, "valid", "default-prefix-rule.json"));

        var defaultResult = RateLimitCompiler.CompileJson(json);
        var optInResult = RateLimitCompiler.CompileJson(json, CompilerOptions.Default with { EmitRateLimitHeaders = true });

        Assert.True(defaultResult.Success);
        Assert.DoesNotContain("X-RateLimit-Remaining-", defaultResult.Xml);
        Assert.DoesNotContain("X-RateLimit-Limit-", defaultResult.Xml);
        Assert.Contains("retry-after-header-name=\"Retry-After\"", defaultResult.Xml);

        Assert.True(optInResult.Success);
        Assert.Contains("X-RateLimit-Remaining-dialogporten-default", optInResult.Xml);
        Assert.Contains("X-RateLimit-Limit-dialogporten-default", optInResult.Xml);
    }

    [Fact]
    public void Client_id_variable_name_can_be_overridden()
    {
        var json = File.ReadAllText(Path.Combine(FixtureRoot, "valid", "default-prefix-rule.json"));

        var result = RateLimitCompiler.CompileJson(json, CompilerOptions.Default with { ClientIdVariableName = "customClientId" });

        Assert.True(result.Success);
        Assert.Contains("context.Variables[&quot;customClientId&quot;]", result.Xml);
        Assert.Contains("name=\"customClientId\"", result.Xml);
        Assert.DoesNotContain("context.Variables[&quot;oauthClientId&quot;]", result.Xml);
        Assert.DoesNotContain("name=\"oauthClientId\"", result.Xml);
    }

    [Fact]
    public void Exclude_rules_are_evaluated_before_limit_rules()
    {
        var json = File.ReadAllText(Path.Combine(FixtureRoot, "valid", "exclude-exact-path.json"));

        var result = RateLimitCompiler.CompileJson(json);

        Assert.True(result.Success);
        var document = XDocument.Parse(result.Xml!);
        var outerChoose = document.Root!.Elements("choose").Skip(1).Single();
        Assert.Contains("/dialogporten/health", outerChoose.Element("when")!.Attribute("condition")!.Value);
        Assert.Empty(outerChoose.Element("when")!.Elements("rate-limit-by-key"));
        Assert.NotNull(outerChoose.Element("otherwise")!.Descendants("rate-limit-by-key").Single());
    }

    [Fact]
    public void Cli_exit_codes_match_contract()
    {
        var valid = Path.Combine(FixtureRoot, "valid", "disabled-config.json");
        var invalid = Path.Combine(FixtureRoot, "invalid", "invalid-calls-renewal.json");

        Assert.Equal(2, Program.Run([], TextWriter.Null, TextWriter.Null));
        Assert.Equal(0, Program.Run(["rate-limit", "--input", valid, "--stdout"], TextWriter.Null, TextWriter.Null));
        Assert.Equal(1, Program.Run(["rate-limit", "--input", invalid, "--stdout"], TextWriter.Null, TextWriter.Null));
        Assert.Equal(2, Program.Run(["rate-limit", "--input", valid, "--stdout", "--client-id-variable-name", "bad/name"], TextWriter.Null, TextWriter.Null));
    }

    public static IEnumerable<object[]> ValidFixtures()
    {
        return Directory.EnumerateFiles(Path.Combine(FixtureRoot, "valid"), "*.json")
            .Order(StringComparer.Ordinal)
            .Select(static x => new object[] { x });
    }

    public static IEnumerable<object[]> InvalidFixtures()
    {
        return Directory.EnumerateFiles(Path.Combine(FixtureRoot, "invalid"), "*.json")
            .Order(StringComparer.Ordinal)
            .Select(static x => new object[] { x });
    }

    private static string FormatDiagnostics(IReadOnlyList<Diagnostic> diagnostics)
    {
        return string.Join(Environment.NewLine, diagnostics.Select(static x => x.ToString())) + Environment.NewLine;
    }
}
