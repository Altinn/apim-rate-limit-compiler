namespace ApimPolicyCompiler.Core;

public sealed record CompilerOptions(
    string ClientIdVariableName,
    bool EmitRateLimitHeaders,
    string? SourceRef = null,
    string? SourceRevision = null,
    string? CompilerVersion = null)
{
    public static CompilerOptions Default { get; } = new("oauthClientId", false);
}
