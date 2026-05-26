using System.Text.Json.Serialization;

namespace ApimPolicyCompiler.Core;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = false,
    GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(RateLimitConfig))]
public sealed partial class RateLimitJsonContext : JsonSerializerContext;
