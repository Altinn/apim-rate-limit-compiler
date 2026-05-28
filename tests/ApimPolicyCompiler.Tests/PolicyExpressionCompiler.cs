using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace ApimPolicyCompiler.Tests;

public interface IPolicyExpressionEvaluator
{
    object? Evaluate(FakeContext context);
}

public sealed class PolicyExpressionCompiler
{
    private static readonly IReadOnlyList<MetadataReference> References = CreateReferences();

    public IPolicyExpressionEvaluator Compile(PolicyExpression expression)
    {
        var source = CreateSource(expression);
        var syntaxTree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.CSharp7_3));
        var compilation = CSharpCompilation.Create(
            "ApimPolicyCompilerExpression_" + Guid.NewGuid().ToString("N"),
            [syntaxTree],
            References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Disable));

        using var stream = new MemoryStream();
        var result = compilation.Emit(stream);
        if (!result.Success)
        {
            var diagnostics = string.Join(Environment.NewLine, result.Diagnostics
                .Where(static x => x.Severity == DiagnosticSeverity.Error)
                .Select(static x => x.ToString()));
            throw new InvalidOperationException(
                $"Failed to compile {expression.SourceDescription}:{Environment.NewLine}{expression.Text}{Environment.NewLine}{diagnostics}");
        }

        stream.Position = 0;
        var assembly = Assembly.Load(stream.ToArray());
        var type = assembly.GetType("ApimPolicyCompiler.Tests.Generated.CompiledPolicyExpression", throwOnError: true)!;
        return (IPolicyExpressionEvaluator)Activator.CreateInstance(type)!;
    }

    public static IReadOnlyList<string> ValidateStaticPolicySubset(IEnumerable<PolicyExpression> expressions)
    {
        var errors = new List<string>();
        string[] denied =
        [
            "Regex",
            "Newtonsoft",
            "JObject",
            "JsonDocument",
            "HttpClient",
            "Task",
            "Thread",
            "Guid.NewGuid",
            "DateTime.Now",
            "Environment.",
            "File.",
            "Directory."
        ];

        foreach (var expression in expressions)
        {
            if (!HasRecognizedShape(expression.Text))
            {
                errors.Add($"{expression.SourceDescription} has an unrecognized APIM expression wrapper.");
            }

            if (expression.Text.Contains("@(@(", StringComparison.Ordinal))
            {
                errors.Add($"{expression.SourceDescription} contains a nested @(@(...)) wrapper.");
            }

            if (expression.Text.Contains("{{", StringComparison.Ordinal) || expression.Text.Contains("}}", StringComparison.Ordinal))
            {
                errors.Add($"{expression.SourceDescription} contains unresolved template markers.");
            }

            foreach (var deniedText in denied)
            {
                if (expression.Text.Contains(deniedText, StringComparison.Ordinal))
                {
                    errors.Add($"{expression.SourceDescription} contains denied API text '{deniedText}'.");
                }
            }
        }

        return errors;
    }

    private static bool HasRecognizedShape(string text)
    {
        return (text.StartsWith("@(", StringComparison.Ordinal) && text.EndsWith(")", StringComparison.Ordinal))
            || (text.StartsWith("@{", StringComparison.Ordinal) && text.EndsWith("}", StringComparison.Ordinal));
    }

    private static string CreateSource(PolicyExpression expression)
    {
        var body = expression.Text.StartsWith("@(", StringComparison.Ordinal)
            ? "return " + expression.Text[2..^1] + ";"
            : expression.Text[2..^1];

        return $$"""
        using System;
        using System.Collections.Generic;
        using ApimPolicyCompiler.Tests;

        namespace ApimPolicyCompiler.Tests.Generated
        {
            public sealed class CompiledPolicyExpression : IPolicyExpressionEvaluator
            {
                public object Evaluate(FakeContext context)
                {
                    {{body}}
                }
            }
        }
        """;
    }

    private static IReadOnlyList<MetadataReference> CreateReferences()
    {
        var trustedPlatformAssemblies = (string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES");
        var references = trustedPlatformAssemblies!
            .Split(Path.PathSeparator)
            .Select(static x => MetadataReference.CreateFromFile(x))
            .Cast<MetadataReference>()
            .ToList();

        references.Add(MetadataReference.CreateFromFile(typeof(IPolicyExpressionEvaluator).Assembly.Location));
        return references;
    }
}
