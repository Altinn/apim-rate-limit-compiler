using System.Text.Json;
using System.Text.Json.Serialization;

namespace ApimPolicyCompiler.Core;

public sealed class RateLimitConfig
{
    [JsonPropertyName("$schema")]
    public string? Schema { get; set; }

    [JsonPropertyName("version")]
    public int Version { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

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

    [JsonPropertyName("action")]
    public string? Action { get; set; }

    [JsonPropertyName("match")]
    public RateLimitMatch? Match { get; set; }

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

public sealed class RateLimitMatch
{
    [JsonPropertyName("methods")]
    public List<string>? Methods { get; set; }

    [JsonPropertyName("pathMode")]
    public string? PathMode { get; set; }

    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("caller")]
    public RateLimitCallerMatch? Caller { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class RateLimitCallerMatch
{
    [JsonPropertyName("clientIds")]
    public List<string>? ClientIds { get; set; }

    [JsonPropertyName("scopes")]
    public List<string>? Scopes { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}
