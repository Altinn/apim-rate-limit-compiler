using System.Text.Encodings.Web;
using ApimRateLimitCompiler.Core;

namespace ApimRateLimitCompiler.Cli;

public static class Program
{
    public static int Main(string[] args)
    {
        return Run(args, Console.Out, Console.Error);
    }

    public static int Run(string[] args, TextWriter stdout, TextWriter stderr)
    {
        var options = CliOptions.Parse(args);
        if (options.Error is not null)
        {
            stderr.WriteLine(options.Error);
            WriteUsage(stderr);
            return 2;
        }

        string json;
        try
        {
            json = File.ReadAllText(options.InputPath!);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            stderr.WriteLine($"Failed to read input file '{options.InputPath}': {ex.Message}");
            return 1;
        }

        var compilerOptions = new CompilerOptions(
            options.ClientIdVariableName!,
            options.EmitRateLimitHeaders,
            options.SourceRef,
            options.SourceRevision);
        var result = RateLimitCompiler.CompileJson(json, compilerOptions);
        var hasWarningFailure = options.FailOnWarning && result.Warnings.Count > 0;
        WriteDiagnostics(result.Diagnostics, options.WarningsAsJson, hasWarningFailure ? DiagnosticSeverity.Error : null, stderr);

        if (!result.Success || hasWarningFailure)
        {
            return 1;
        }

        if (options.Stdout)
        {
            stdout.Write(result.Xml);
        }

        if (options.OutputPath is not null)
        {
            try
            {
                var directory = Path.GetDirectoryName(options.OutputPath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                File.WriteAllText(options.OutputPath, result.Xml);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                stderr.WriteLine($"Failed to write output file '{options.OutputPath}': {ex.Message}");
                return 1;
            }
        }

        if (options.HashPath is not null)
        {
            try
            {
                var directory = Path.GetDirectoryName(options.HashPath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                File.WriteAllText(options.HashPath, result.Sha256 + Environment.NewLine);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                stderr.WriteLine($"Failed to write hash file '{options.HashPath}': {ex.Message}");
                return 1;
            }
        }

        return 0;
    }

    private static void WriteDiagnostics(IReadOnlyList<Diagnostic> diagnostics, bool warningsAsJson, DiagnosticSeverity? warningOverride, TextWriter stderr)
    {
        if (diagnostics.Count == 0)
        {
            return;
        }

        if (warningsAsJson)
        {
            stderr.WriteLine("[");
            for (var i = 0; i < diagnostics.Count; i++)
            {
                var diagnostic = diagnostics[i];
                var severity = warningOverride is not null && diagnostic.Severity == DiagnosticSeverity.Warning
                    ? warningOverride.Value
                    : diagnostic.Severity;
                stderr.Write("  { ");
                stderr.Write($"\"severity\": {JsonString(severity.ToString().ToLowerInvariant())}, ");
                stderr.Write($"\"code\": {JsonString(diagnostic.Code)}, ");
                stderr.Write($"\"message\": {JsonString(diagnostic.Message)}, ");
                stderr.Write($"\"target\": {JsonString(diagnostic.Target)}");
                stderr.WriteLine(i == diagnostics.Count - 1 ? " }" : " },");
            }
            stderr.WriteLine("]");
            return;
        }

        foreach (var diagnostic in diagnostics)
        {
            if (warningOverride is not null && diagnostic.Severity == DiagnosticSeverity.Warning)
            {
                stderr.WriteLine(diagnostic with { Severity = warningOverride.Value });
            }
            else
            {
                stderr.WriteLine(diagnostic);
            }
        }
    }

    private static void WriteUsage(TextWriter writer)
    {
        writer.WriteLine("Usage: apim-rate-limit-compiler rate-limit --input <file> [--output <file>] [--stdout] [--write-hash <file>] [--fail-on-warning] [--warnings-as-json] [--client-id-variable-name <name>] [--emit-rate-limit-headers] [--source-ref <value>] [--source-revision <value>]");
    }

    private static string JsonString(string? value)
    {
        return value is null ? "null" : "\"" + JavaScriptEncoder.Default.Encode(value) + "\"";
    }
}

internal sealed class CliOptions
{
    public string? InputPath { get; private init; }

    public string? OutputPath { get; private init; }

    public string? HashPath { get; private init; }

    public bool Stdout { get; private init; }

    public bool FailOnWarning { get; private init; }

    public bool WarningsAsJson { get; private init; }

    public string? ClientIdVariableName { get; private init; }

    public bool EmitRateLimitHeaders { get; private init; }

    public string? SourceRef { get; private init; }

    public string? SourceRevision { get; private init; }

    public string? Error { get; private init; }

    public static CliOptions Parse(string[] args)
    {
        if (args.Length == 0 || args[0] != "rate-limit")
        {
            return new CliOptions { Error = "Missing command 'rate-limit'." };
        }

        string? input = null;
        string? output = null;
        string? hash = null;
        var stdout = false;
        var failOnWarning = false;
        var warningsAsJson = false;
        var clientIdVariableName = CompilerOptions.Default.ClientIdVariableName;
        var emitRateLimitHeaders = false;
        string? sourceRef = null;
        string? sourceRevision = null;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--input":
                    if (!ReadValue(args, ref i, out input))
                    {
                        return new CliOptions { Error = "--input requires a value." };
                    }
                    break;
                case "--output":
                    if (!ReadValue(args, ref i, out output))
                    {
                        return new CliOptions { Error = "--output requires a value." };
                    }
                    break;
                case "--write-hash":
                    if (!ReadValue(args, ref i, out hash))
                    {
                        return new CliOptions { Error = "--write-hash requires a value." };
                    }
                    break;
                case "--stdout":
                    stdout = true;
                    break;
                case "--fail-on-warning":
                    failOnWarning = true;
                    break;
                case "--warnings-as-json":
                    warningsAsJson = true;
                    break;
                case "--client-id-variable-name":
                    if (!ReadValue(args, ref i, out clientIdVariableName))
                    {
                        return new CliOptions { Error = "--client-id-variable-name requires a value." };
                    }
                    if (!IsSafeVariableName(clientIdVariableName))
                    {
                        return new CliOptions { Error = "--client-id-variable-name may only contain letters, digits, '-' and '_'." };
                    }
                    break;
                case "--emit-rate-limit-headers":
                    emitRateLimitHeaders = true;
                    break;
                case "--source-ref":
                    if (!ReadValue(args, ref i, out sourceRef))
                    {
                        return new CliOptions { Error = "--source-ref requires a value." };
                    }
                    break;
                case "--source-revision":
                    if (!ReadValue(args, ref i, out sourceRevision))
                    {
                        return new CliOptions { Error = "--source-revision requires a value." };
                    }
                    break;
                default:
                    return new CliOptions { Error = $"Unknown argument '{args[i]}'." };
            }
        }

        if (input is null)
        {
            return new CliOptions { Error = "--input is required." };
        }

        if (output is null && !stdout)
        {
            return new CliOptions { Error = "Either --output or --stdout is required." };
        }

        return new CliOptions
        {
            InputPath = input,
            OutputPath = output,
            HashPath = hash,
            Stdout = stdout,
            FailOnWarning = failOnWarning,
            WarningsAsJson = warningsAsJson,
            ClientIdVariableName = clientIdVariableName,
            EmitRateLimitHeaders = emitRateLimitHeaders,
            SourceRef = sourceRef,
            SourceRevision = sourceRevision
        };
    }

    private static bool ReadValue(string[] args, ref int index, out string? value)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
        {
            value = null;
            return false;
        }

        value = args[++index];
        return true;
    }

    private static bool IsSafeVariableName(string? value)
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
}
