using System.Collections.Concurrent;
using System.Reflection;

namespace ForgePoint.Auditing;

/// <summary>
/// Attributes only work on types you own. IdentityUser, IdentityUserToken and
/// anything else from a framework package has to be configured here instead -
/// otherwise PasswordHash and SecurityStamp land in the trail in the clear.
///
/// Registry entries and attributes are merged; the registry wins on conflict.
/// </summary>
public sealed class AuditTypeRegistry
{
    private readonly Dictionary<Type, TypeRules> _rules = [];
    private readonly ConcurrentDictionary<Type, TypePolicy> _resolved = new();

    public TypeRuleBuilder<T> ForType<T>() => new(GetOrAdd(typeof(T)));

    /// <summary>
    /// Sensible defaults for ASP.NET Core Identity. Call this if your Identity
    /// tables live in an audited context.
    /// </summary>
    public AuditTypeRegistry WithIdentityDefaults<TUser, TKey>()
        where TUser : class
        where TKey : IEquatable<TKey>
    {
        ForType<TUser>()
            .NoTechnicalData()
            .Redact("PasswordHash", "SecurityStamp", "ConcurrencyStamp",
                    "PhoneNumber", "NormalizedEmail", "NormalizedUserName");

        // Token values are credentials. The fact a token was issued is an authn
        // event worth keeping; the value is not.
        ForTypeName("Microsoft.AspNetCore.Identity.IdentityUserToken`1")
            .NoTechnicalData().Redact("Value");

        ForTypeName("Microsoft.AspNetCore.Identity.IdentityUserLogin`1")
            .NoTechnicalData().Redact("ProviderKey");

        ForTypeName("Microsoft.AspNetCore.Identity.IdentityRole`1").NoTechnicalData();
        ForTypeName("Microsoft.AspNetCore.Identity.IdentityUserRole`1").NoTechnicalData();
        ForTypeName("Microsoft.AspNetCore.Identity.IdentityUserClaim`1").NoTechnicalData();
        ForTypeName("Microsoft.AspNetCore.Identity.IdentityRoleClaim`1").NoTechnicalData();

        return this;
    }

    /// <summary>Match by open generic type name, since IdentityUserToken&lt;TKey&gt; varies.</summary>
    public TypeRuleBuilder<object> ForTypeName(string fullName)
    {
        var rules = _byName.TryGetValue(fullName, out var existing)
            ? existing
            : _byName[fullName] = new TypeRules();
        return new TypeRuleBuilder<object>(rules);
    }

    private readonly Dictionary<string, TypeRules> _byName = [];

    private TypeRules GetOrAdd(Type t) =>
        _rules.TryGetValue(t, out var r) ? r : _rules[t] = new TypeRules();

    internal TypePolicy PolicyFor(Type? type)
    {
        if (type is null) return TypePolicy.Default;

        return _resolved.GetOrAdd(type, t =>
        {
            var redacted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var excluded = t.GetCustomAttribute<AuditExcludeAttribute>() is not null;
            bool? noTechnicalData = t.GetCustomAttribute<NoTechnicalDataAttribute>() is not null
                ? true : null;

            foreach (var p in t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
                if (p.GetCustomAttribute<AuditRedactAttribute>() is not null)
                    redacted.Add(p.Name);

            // Walk the type and its bases so IdentityUser rules apply to
            // ApplicationUser : IdentityUser without repeating them.
            foreach (var candidate in Hierarchy(t))
            {
                if (_rules.TryGetValue(candidate, out var byType))
                    Apply(byType);

                var open = candidate.IsGenericType
                    ? candidate.GetGenericTypeDefinition().FullName
                    : candidate.FullName;

                if (open is not null && _byName.TryGetValue(open, out var byName))
                    Apply(byName);
            }

            return new TypePolicy(excluded, noTechnicalData ?? false, redacted);

            void Apply(TypeRules r)
            {
                excluded |= r.Excluded;
                if (r.NoTechnicalData) noTechnicalData = true;
                redacted.UnionWith(r.Redacted);
            }
        });
    }

    private static IEnumerable<Type> Hierarchy(Type t)
    {
        for (var c = t; c is not null && c != typeof(object); c = c.BaseType)
            yield return c;
    }

    public sealed class TypeRules
    {
        public bool Excluded { get; set; }
        public bool NoTechnicalData { get; set; }
        public HashSet<string> Redacted { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public sealed class TypeRuleBuilder<T>(TypeRules rules)
    {
        /// <summary>Never audit this type at all.</summary>
        public TypeRuleBuilder<T> Exclude() { rules.Excluded = true; return this; }

        /// <summary>Type carries no export-controlled technical data.</summary>
        public TypeRuleBuilder<T> NoTechnicalData() { rules.NoTechnicalData = true; return this; }

        /// <summary>Record that these columns changed, never their values.</summary>
        public TypeRuleBuilder<T> Redact(params string[] properties)
        {
            foreach (var p in properties) rules.Redacted.Add(p);
            return this;
        }
    }
}

internal sealed record TypePolicy(bool Excluded, bool NoTechnicalData, HashSet<string> Redacted)
{
    public static readonly TypePolicy Default =
        new(false, false, new HashSet<string>(StringComparer.OrdinalIgnoreCase));

    public bool IsRedacted(string column) => Redacted.Contains(column);
}