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
    public void Cli_exit_codes_match_contract()
    {
        var valid = Path.Combine(FixtureRoot, "valid", "disabled-config.json");
        var invalid = Path.Combine(FixtureRoot, "invalid", "invalid-calls-renewal.json");

        Assert.Equal(2, Program.Run([], TextWriter.Null, TextWriter.Null));
        Assert.Equal(0, Program.Run(["rate-limit", "--input", valid, "--stdout"], TextWriter.Null, TextWriter.Null));
        Assert.Equal(1, Program.Run(["rate-limit", "--input", invalid, "--stdout"], TextWriter.Null, TextWriter.Null));
        Assert.Equal(1, Program.Run(["rate-limit", "--input", Path.Combine(FixtureRoot, "valid", "overlapping-warning.json"), "--stdout", "--fail-on-warning"], TextWriter.Null, TextWriter.Null));
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
