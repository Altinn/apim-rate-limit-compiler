using System.Text.Json.Serialization;

namespace Altinn.ApimPolicyCompiler.Core;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = false,
    GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(RateLimitConfig))]
public sealed partial class RateLimitJsonContext : JsonSerializerContext;
