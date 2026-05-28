using System.Xml.Linq;

namespace ApimPolicyCompiler.Tests;

public sealed record PolicyExpression(
    // ReSharper disable once NotAccessedPositionalProperty.Global
    string ElementName,
    // ReSharper disable once NotAccessedPositionalProperty.Global
    string AttributeName,
    string Text,
    string SourceDescription);

public static class PolicyExpressionExtractor
{
    public static IReadOnlyList<PolicyExpression> Extract(XDocument document)
    {
        var expressions = new List<PolicyExpression>();

        foreach (var element in document.Descendants())
        {
            ExtractAttribute(expressions, element, "when", "condition");
            ExtractAttribute(expressions, element, "set-variable", "value");
            ExtractAttribute(expressions, element, "rate-limit-by-key", "counter-key");
        }

        return expressions;
    }

    private static void ExtractAttribute(List<PolicyExpression> expressions, XElement element, string elementName, string attributeName)
    {
        if (element.Name.LocalName != elementName)
        {
            return;
        }

        var value = element.Attribute(attributeName)?.Value;
        if (value is null)
        {
            return;
        }

        expressions.Add(new PolicyExpression(
            elementName,
            attributeName,
            value,
            $"{elementName}/@{attributeName}"));
    }
}
