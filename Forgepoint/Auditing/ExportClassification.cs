using System.Collections.Concurrent;
using System.Reflection;
using Microsoft.Extensions.Caching.Memory;

namespace ForgePoint.Auditing;

public enum ExportJurisdiction
{
    /// <summary>No determination on file yet. Handled as controlled, reported separately.</summary>
    Undetermined,
    NotControlled,
    Ear,
    Itar
}

/// <summary>
/// A classification snapshot for one item at one moment. Immutable by design -
/// the audit row stores what was true when the event happened, never a
/// reference that later resolves to something else.
/// </summary>
public sealed record ExportClassification
{
    public ExportJurisdiction Jurisdiction { get; init; } = ExportJurisdiction.Undetermined;

    /// <summary>USML category, e.g. "XII(e)". ITAR only.</summary>
    public string? UsmlCategory { get; init; }

    /// <summary>ECCN, e.g. "9E991" or "EAR99". EAR only.</summary>
    public string? Eccn { get; init; }

    /// <summary>Reference to the determination record that authorises this.</summary>
    public string? DeterminationId { get; init; }

    public DateTime? ClassifiedUtc { get; init; }

    /// <summary>Undetermined counts as controlled for handling purposes.</summary>
    public bool RequiresControl =>
        Jurisdiction is ExportJurisdiction.Itar
                     or ExportJurisdiction.Ear
                     or ExportJurisdiction.Undetermined;

    public static readonly ExportClassification Undetermined = new();

    public static readonly ExportClassification NotControlled =
        new() { Jurisdiction = ExportJurisdiction.NotControlled };

    public static ExportClassification Itar(string usmlCategory, string determinationId, DateTime classifiedUtc) =>
        new()
        {
            Jurisdiction    = ExportJurisdiction.Itar,
            UsmlCategory    = usmlCategory,
            DeterminationId = determinationId,
            ClassifiedUtc   = classifiedUtc
        };

    public static ExportClassification Ear(string eccn, string determinationId, DateTime classifiedUtc) =>
        new()
        {
            Jurisdiction    = ExportJurisdiction.Ear,
            Eccn            = eccn,
            DeterminationId = determinationId,
            ClassifiedUtc   = classifiedUtc
        };
}

/// <summary>
/// Implemented by the entity that actually carries a determination - typically
/// Part, or Part+Revision if you classify per revision.
/// </summary>
public interface IExportClassified
{
    ExportClassification ExportClassification { get; }
}

/// <summary>
/// Implemented by everything downstream of a classified item: NC programs,
/// setup sheets, operations, inspection records, fixtures. Classification is
/// inherited from the source rather than duplicated.
/// </summary>
public interface IExportDerived
{
    /// <summary>Entity type name and key of the item this inherits from.</summary>
    (string Type, string Key) ClassificationSource { get; }
}

/// <summary>
/// Marks a type as carrying no technical data at all - shop config, user
/// preferences, scheduling metadata, lookup tables. Required: a type that
/// implements neither classification interface and lacks this attribute
/// resolves to Undetermined and is logged once as a gap.
/// </summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class NoTechnicalDataAttribute : Attribute;

public interface IExportClassificationResolver
{
    ValueTask<ExportClassification> ResolveAsync(object entity, CancellationToken ct = default);

    ValueTask<ExportClassification> ResolveAsync(
        string entityType, string entityKey, CancellationToken ct = default);

    /// <summary>Call immediately after a determination changes. Cache staleness is
    /// tolerable for reporting but not for an access decision.</summary>
    void Invalidate(string entityType, string entityKey);
}

/// <summary>
/// Loads classifications for source items. Implement against whatever table
/// holds your determinations; this is the one piece that has to know your
/// domain schema.
/// </summary>
public interface IExportClassificationStore
{
    Task<ExportClassification?> LoadAsync(
        string entityType, string entityKey, CancellationToken ct = default);
}

public sealed class ExportClassificationResolver(
    IExportClassificationStore store,
    IMemoryCache cache,
    ILogger<ExportClassificationResolver> log) : IExportClassificationResolver
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(60);
    private static readonly ConcurrentDictionary<Type, byte> GapsReported = new();

    public async ValueTask<ExportClassification> ResolveAsync(
        object entity, CancellationToken ct = default)
    {
        switch (entity)
        {
            // The item carries its own determination: authoritative, no lookup.
            case IExportClassified self:
                return self.ExportClassification;

            // Inherits from an upstream item.
            case IExportDerived derived:
            {
                var (type, key) = derived.ClassificationSource;
                return await ResolveAsync(type, key, ct);
            }

            default:
            {
                var t = entity.GetType();
                if (t.GetCustomAttribute<NoTechnicalDataAttribute>() is not null)
                    return ExportClassification.NotControlled;

                // Fail safe, and make the gap discoverable rather than silent.
                if (GapsReported.TryAdd(t, 0))
                    log.LogWarning(
                        "{Type} implements neither IExportClassified nor IExportDerived and is " +
                        "not marked [NoTechnicalData]. Its audit rows will be recorded as " +
                        "Undetermined until it is classified.", t.FullName);

                return ExportClassification.Undetermined;
            }
        }
    }

    public async ValueTask<ExportClassification> ResolveAsync(
        string entityType, string entityKey, CancellationToken ct = default)
    {
        var cacheKey = Key(entityType, entityKey);
        if (cache.TryGetValue<ExportClassification>(cacheKey, out var hit) && hit is not null)
            return hit;

        var loaded = await store.LoadAsync(entityType, entityKey, ct)
                     ?? ExportClassification.Undetermined;

        cache.Set(cacheKey, loaded, Ttl);
        return loaded;
    }

    public void Invalidate(string entityType, string entityKey) =>
        cache.Remove(Key(entityType, entityKey));

    private static string Key(string type, string key) => $"xc:{type}:{key}";
}

/// <summary>
/// Reclassification is itself an auditable event, and the one an assessor or
/// DDTC reviewer will ask about first. Route every determination change
/// through here rather than writing the domain row directly.
/// </summary>
public sealed class ReclassificationService(
    IAuditLogger audit,
    IExportClassificationResolver resolver)
{
    public async Task RecordAsync(
        string entityType,
        string entityKey,
        ExportClassification previous,
        ExportClassification updated,
        string authority,      // 'CJ ruling', 'customer flowdown', 'internal determination'
        string reference,      // ruling number, contract line, memo ID
        string justification,
        CancellationToken ct = default)
    {
        await audit.LogAsync(new AuditRecordRequest(
            AuditEventType.Reclassification, AuditAction.Update, AuditOutcome.Success)
        {
            EntityType     = entityType,
            EntityKey      = entityKey,
            Classification = updated,
            Reason         = justification,
            Detail = new
            {
                from = new
                {
                    jurisdiction = previous.Jurisdiction.ToString(),
                    usml = previous.UsmlCategory,
                    eccn = previous.Eccn,
                    determination = previous.DeterminationId
                },
                to = new
                {
                    jurisdiction = updated.Jurisdiction.ToString(),
                    usml = updated.UsmlCategory,
                    eccn = updated.Eccn,
                    determination = updated.DeterminationId
                },
                authority,
                reference,
                // Flag the case that needs an exposure review.
                escalation = updated.Jurisdiction > previous.Jurisdiction
            }
        }, ct);

        resolver.Invalidate(entityType, entityKey);
    }
}
