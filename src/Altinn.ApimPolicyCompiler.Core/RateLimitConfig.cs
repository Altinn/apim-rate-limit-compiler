using System.Text.Json;
using System.Text.Json.Serialization;

namespace Altinn.ApimPolicyCompiler.Core;

public sealed class RateLimitConfig
{
    [JsonPropertyName("version")]
    public int Version { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("rules")]
    public List<RateLimitRule>? Rules { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RateLimitRule
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("methods")]
    public List<string>? Methods { get; set; }

    [JsonPropertyName("pathMode")]
    public string? PathMode { get; set; }

    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("keyMode")]
    public string? KeyMode { get; set; }

    [JsonPropertyName("keyClaimName")]
    public string? KeyClaimName { get; set; }

    [JsonPropertyName("calls")]
    public int Calls { get; set; }

    [JsonPropertyName("renewalPeriod")]
    public int RenewalPeriod { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}
