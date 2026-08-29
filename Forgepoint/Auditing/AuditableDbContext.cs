using Audit.Core.Providers;
using Audit.EntityFramework;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace ForgePoint.Auditing;

/// <summary>
/// Marker so the factory and DI can talk about audited contexts without
/// caring which base class they came from.
/// </summary>
public interface IAuditableContext
{
    AuditSaveCoordinator Coordinator { get; }
}

/// <summary>
/// The actual save logic, factored out because C# has single inheritance and
/// AuditDbContext and AuditIdentityDbContext are two separate roots. Both base
/// classes below delegate here, so there is one implementation of the
/// fail-closed behaviour rather than two that drift.
/// </summary>
public sealed class AuditSaveCoordinator(
    ICurrentUser user,
    AuditWriter writer,
    EfEventMapper mapper)
{
    public async Task<int> SaveAsync(
        DbContext db,
        Func<CancellationToken, Task<EntityFrameworkEvent>> save,
        CancellationToken ct)
    {
        // Fail fast if we cannot attribute the change (3.3.2). Accessing Id
        // throws UnattributedActionException when no principal is established.
        _ = user.Id;

        var ownsTransaction = db.Database.CurrentTransaction is null;
        IDbContextTransaction tx = db.Database.CurrentTransaction
            ?? await db.Database.BeginTransactionAsync(ct);

        try
        {
            var efEvent = await save(ct);
            var records = await mapper.MapAsync(efEvent, user, ct);

            if (records.Count > 0)
            {
                await writer.WriteAsync(
                    db.Database.GetDbConnection(),
                    tx.GetDbTransaction(),
                    records,
                    $"SaveChanges/{db.GetType().Name}",
                    ct);
            }

            if (ownsTransaction) await tx.CommitAsync(ct);

            // NOTE: property name is version-sensitive in Audit.EntityFramework.
            return efEvent.Result;
        }
        catch
        {
            if (ownsTransaction)
            {
                try { await tx.RollbackAsync(CancellationToken.None); }
                catch { /* connection already broken; the transaction dies with it */ }
            }
            throw;
        }
        finally
        {
            if (ownsTransaction) await tx.DisposeAsync();
        }
    }

    /// <summary>Shared configuration applied by both base classes.</summary>
    public static void Configure(IAuditDbContext ctx)
    {
        // We persist the event ourselves, on our own connection and transaction.
        ctx.AuditDataProvider = new NullDataProvider();
        ctx.ExcludeValidationResults = true;

        // Diffs only in the payload - full snapshots widen the CUI surface.
        // entry.Entity is still populated in the event, which is what the
        // classification resolver needs; this flag only controls serialisation.
        ctx.IncludeEntityObjects = false;
    }

    public static NotSupportedException SyncSaveNotSupported() => new(
        "Use SaveChangesAsync. Synchronous saves cannot write the audit row " +
        "without blocking the circuit's synchronisation context.");
}

/// <summary>
/// Base for business contexts. Writes audit rows inside the same transaction
/// as the data change; if the audit insert fails, the business change is rolled
/// back and an alert is raised (3.3.4).
/// </summary>
public abstract class AuditableDbContext(
    DbContextOptions options,
    AuditSaveCoordinator coordinator)
    : AuditDbContext(options), IAuditableContext
{
    public AuditSaveCoordinator Coordinator { get; } = coordinator;

    protected void ConfigureAuditing() => AuditSaveCoordinator.Configure(this);

    public override int SaveChanges(bool acceptAllChangesOnSuccess) =>
        throw AuditSaveCoordinator.SyncSaveNotSupported();

    public override Task<int> SaveChangesAsync(
        bool acceptAllChangesOnSuccess, CancellationToken ct = default)
        => Coordinator.SaveAsync(this,
            token => this.SaveChangesGetAuditAsync(acceptAllChangesOnSuccess, token), ct);
}

/// <summary>
/// Same behaviour, for a context that must also be an IdentityDbContext.
///
/// Prefer splitting Identity into its own context if you can - Identity tables
/// have a different grant surface, migrate on their own schedule, and their
/// writes (security stamps, lockout counters, token refresh) add noise to a
/// trail you want dominated by technical-data events. Use this when you cannot.
///
/// Register Identity types with the AuditTypeRegistry before using this, or
/// PasswordHash and SecurityStamp will be recorded in the clear.
/// </summary>
public abstract class AuditableIdentityDbContext<TUser, TRole, TKey>(
    DbContextOptions options,
    AuditSaveCoordinator coordinator)
    : AuditIdentityDbContext<TUser, TRole, TKey>(options), IAuditableContext
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TKey : IEquatable<TKey>
{
    public AuditSaveCoordinator Coordinator { get; } = coordinator;

    protected void ConfigureAuditing() => AuditSaveCoordinator.Configure(this);

    public override int SaveChanges(bool acceptAllChangesOnSuccess) =>
        throw AuditSaveCoordinator.SyncSaveNotSupported();

    public override Task<int> SaveChangesAsync(
        bool acceptAllChangesOnSuccess, CancellationToken ct = default)
        => Coordinator.SaveAsync(this,
            token => this.SaveChangesGetAuditAsync(acceptAllChangesOnSuccess, token), ct);
}

/// <summary>
/// Turns an Audit.NET EntityFrameworkEvent into audit rows, applying redaction
/// and resolving each entity's export classification individually.
/// </summary>
public sealed class EfEventMapper(
    IExportClassificationResolver classifier,
    AuditTypeRegistry registry)
{
    public async Task<IReadOnlyList<AuditRecord>> MapAsync(
        EntityFrameworkEvent efEvent, ICurrentUser user, CancellationToken ct)
    {
        var records = new List<AuditRecord>(efEvent.Entries.Count);

        foreach (var entry in efEvent.Entries)
        {
            var policy = registry.PolicyFor(entry.EntityType);
            if (policy.Excluded) continue;

            var changes = BuildPayload(entry, policy);

            // An update whose only changed columns were no-ops produces no row.
            if (entry.Action == "Update" && changes is { Count: 0 }) continue;

            // Classification is per instance, not per type: this shop runs
            // controlled and uncontrolled work through the same tables.
            var classification = policy.NoTechnicalData
                ? ExportClassification.NotControlled
                : entry.Entity is not null
                    ? await classifier.ResolveAsync(entry.Entity, ct)
                    : ExportClassification.Undetermined;

            records.Add(new AuditRecord
            {
                EventType      = AuditEventType.EntityChange,
                Action         = entry.Action,
                Outcome        = efEvent.Success ? AuditOutcome.Success : AuditOutcome.Failure,
                ActorId        = user.Id,
                ActorName      = user.Name,
                ActorKind      = user.Kind,
                ClientIp       = user.ClientIp,
                CircuitId      = user.CircuitId,
                CorrelationId  = user.CorrelationId,
                EntityType     = entry.EntityType?.Name ?? entry.Name,
                EntityKey      = FormatKey(entry),
                Classification = classification,
                DetailJson     = AuditJson.Serialize(new
                {
                    table = entry.Table,
                    schema = entry.Schema,
                    error = efEvent.ErrorMessage
                }),
                ChangesJson = changes is null ? null : AuditJson.Serialize(changes)
            });
        }

        return records;
    }

    /// <summary>
    /// Update entries carry per-column diffs. Insert and Delete entries do not -
    /// Audit.NET puts the row contents in ColumnValues instead. Reading only
    /// Changes would give you a delete row that records THAT a PO was deleted
    /// but not WHAT was in it, which is the one thing anyone will ask for.
    /// </summary>
    private static List<object>? BuildPayload(EventEntry entry, TypePolicy policy)
    {
        if (entry.Action == "Update")
        {
            if (entry.Changes is null) return null;

            var diffs = entry.Changes
                .Where(c => !policy.IsRedacted(c.ColumnName))
                .Select(object (c) => new
                {
                    column = c.ColumnName,
                    old = c.OriginalValue,
                    @new = c.NewValue
                })
                .ToList();

            // Redacted columns are still acknowledged as having changed, without
            // either value. "Password was reset" is auditable; the hash is not.
            diffs.AddRange(entry.Changes
                .Where(c => policy.IsRedacted(c.ColumnName))
                .Select(object (c) => new
                {
                    column = c.ColumnName,
                    old = (object?)"[redacted]",
                    @new = (object?)"[redacted]"
                }));

            return diffs;
        }

        // Insert: the row as created. Delete: the row as it was, which is the
        // only surviving copy once the business row is gone.
        if (entry.ColumnValues is null) return null;

        return entry.ColumnValues
            .Select(object (kv) => new
            {
                column = kv.Key,
                value = policy.IsRedacted(kv.Key) ? "[redacted]" : kv.Value
            })
            .ToList();
    }

    private static string? FormatKey(EventEntry entry) =>
        entry.PrimaryKey is null or { Count: 0 }
            ? null
            : string.Join('|', entry.PrimaryKey.Values.Select(v => v?.ToString() ?? ""));
}