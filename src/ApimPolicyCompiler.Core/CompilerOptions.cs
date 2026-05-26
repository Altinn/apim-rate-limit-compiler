namespace ApimPolicyCompiler.Core;

public sealed record CompilerOptions(string ClientIdVariableName, bool EmitRateLimitHeaders)
{
    public static CompilerOptions Default { get; } = new("oauthClientId", false);
}
