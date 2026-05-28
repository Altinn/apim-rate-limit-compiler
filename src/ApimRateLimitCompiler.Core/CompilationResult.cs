namespace ApimRateLimitCompiler.Core;

public sealed record CompilationResult(
    bool Success,
    string? Xml,
    string? Sha256,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public IReadOnlyList<Diagnostic> Errors => Diagnostics.Where(static x => x.Severity == DiagnosticSeverity.Error).ToArray();

    public IReadOnlyList<Diagnostic> Warnings => Diagnostics.Where(static x => x.Severity == DiagnosticSeverity.Warning).ToArray();
}

public sealed record Diagnostic(DiagnosticSeverity Severity, string Code, string Message, string? Target = null)
{
    public override string ToString()
    {
        return Target is null
            ? $"{Severity.ToString().ToUpperInvariant()} {Code}: {Message}"
            : $"{Severity.ToString().ToUpperInvariant()} {Code} [{Target}]: {Message}";
    }
}

public enum DiagnosticSeverity
{
    Error,
    Warning
}
