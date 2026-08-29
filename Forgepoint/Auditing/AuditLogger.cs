using Npgsql;

namespace ForgePoint.Auditing;

public sealed record AuditRecordRequest(string EventType, string Action, string Outcome)
{
    public string? EntityType { get; init; }
    public string? EntityKey  { get; init; }
    public object? Detail     { get; init; }
    public string? Reason     { get; init; }

    /// <summary>
    /// Supply when you already hold the item's classification. Leave null and
    /// the logger resolves it from EntityType/EntityKey; if that is not
    /// possible the row is recorded as Undetermined, never as NotControlled.
    /// </summary>
    public ExportClassification? Classification { get; init; }
}

/// <summary>
/// Everything EF cannot see. Under ITAR this is the larger half of the job:
/// viewing a drawing or pushing a program to a control is a technical data
/// transfer even though nothing in the database changed.
/// </summary>
public interface IAuditLogger
{
    Task LogAsync(AuditRecordRequest request, CancellationToken ct = default);

    /// <summary>
    /// Records access to an item and returns only once the record is durably
    /// written. Callers MUST NOT release the data if this throws - an unlogged
    /// view by an unverified person is the deemed-export scenario.
    /// </summary>
    Task RecordAccessAsync(
        string entityType, string entityKey, string action,
        ExportClassification? classification = null, object? detail = null,
        CancellationToken ct = default);

    Task DeniedAsync(string entityType, string? entityKey, string requirement,
        CancellationToken ct = default);

    /// <summary>
    /// For events that happen before a principal exists - failed logons,
    /// unknown-user attempts, lockouts. There is no circuit, so the caller
    /// supplies the client IP from HttpContext.
    ///
    /// Do not reach for this to work around an UnattributedActionException on
    /// an authenticated path. That exception is telling you something real.
    /// </summary>
    Task LogUnattributedAsync(
        AuditRecordRequest request, string? clientIp, CancellationToken ct = default);
}

public sealed class AuditLogger(
    ICurrentUser user,
    AuditWriter writer,
    IExportClassificationResolver classifier,
    [FromKeyedServices(AuditServiceKeys.AppDataSource)] NpgsqlDataSource dataSource)
    : IAuditLogger
{
    public async Task LogAsync(AuditRecordRequest request, CancellationToken ct = default)
    {
        var classification = request.Classification;

        if (classification is null && request.EntityType is not null && request.EntityKey is not null)
            classification = await classifier.ResolveAsync(request.EntityType, request.EntityKey, ct);

        var record = new AuditRecord
        {
            EventType      = request.EventType,
            Action         = request.Action,
            Outcome        = request.Outcome,
            ActorId        = user.Id,          // throws if unattributable - by design
            ActorName      = user.Name,
            ActorKind      = user.Kind,
            ClientIp       = user.ClientIp,
            CircuitId      = user.CircuitId,
            CorrelationId  = user.CorrelationId,
            EntityType     = request.EntityType,
            EntityKey      = request.EntityKey,
            Classification = classification ?? ExportClassification.Undetermined,
            Reason         = request.Reason,
            DetailJson     = request.Detail is null ? "{}" : AuditJson.Serialize(request.Detail)
        };

        await writer.WriteAsync(dataSource, [record],
            $"{request.EventType}/{request.Action}", ct);
    }

    public Task RecordAccessAsync(
        string entityType, string entityKey, string action,
        ExportClassification? classification = null, object? detail = null,
        CancellationToken ct = default)
        => LogAsync(new AuditRecordRequest(
                AuditEventType.DataAccess, action, AuditOutcome.Success)
            {
                EntityType     = entityType,
                EntityKey      = entityKey,
                Detail         = detail,
                Classification = classification
            }, ct);

    public Task LogUnattributedAsync(
        AuditRecordRequest request, string? clientIp, CancellationToken ct = default)
    {
        var record = new AuditRecord
        {
            EventType      = request.EventType,
            Action         = request.Action,
            Outcome        = request.Outcome,
            ActorId        = "anonymous",
            ActorName      = "anonymous",
            ActorKind      = ActorKind.Anonymous,
            ClientIp       = clientIp,
            CorrelationId  = Guid.NewGuid(),
            EntityType     = request.EntityType,
            EntityKey      = request.EntityKey,
            Classification = ExportClassification.NotControlled,
            Reason         = request.Reason,
            DetailJson     = request.Detail is null ? "{}" : AuditJson.Serialize(request.Detail)
        };

        return writer.WriteAsync(dataSource, [record],
            $"{request.EventType}/{request.Action}", ct);
    }

    public Task DeniedAsync(string entityType, string? entityKey, string requirement,
        CancellationToken ct = default)
        => LogAsync(new AuditRecordRequest(
                AuditEventType.Authz, AuditAction.Denied, AuditOutcome.Denied)
            {
                EntityType = entityType,
                EntityKey  = entityKey,
                Detail     = new { requirement }
            }, ct);
}

/// <summary>
/// Guard for releasing an item to a user or a machine. Resolves the item's
/// classification, logs the access, and only then hands the data over.
///
///   var program = await _guard.ReleaseAsync(
///       "NcProgram", id.ToString(), AuditAction.Download,
///       () => _repo.GetProgramAsync(id));
///
/// Non-controlled items still generate an access row - you need the negative
/// evidence as much as the positive, and the classification snapshot is what
/// proves the item was non-controlled at the time.
/// </summary>
public sealed class ControlledDataGuard(
    IAuditLogger audit,
    IExportClassificationResolver classifier)
{
    public async Task<T> ReleaseAsync<T>(
        string entityType,
        string entityKey,
        string action,
        Func<Task<T>> load,
        object? detail = null,
        CancellationToken ct = default)
    {
        var classification = await classifier.ResolveAsync(entityType, entityKey, ct);
        await audit.RecordAccessAsync(entityType, entityKey, action, classification, detail, ct);
        return await load();
    }

    /// <summary>
    /// Load first, classify from the loaded object, then log and release. Use
    /// when the item carries its own determination (IExportClassified) and a
    /// key-based lookup would be a second round trip.
    /// </summary>
    public async Task<T> ReleaseLoadedAsync<T>(
        string entityType,
        string entityKey,
        string action,
        Func<Task<T>> load,
        object? detail = null,
        CancellationToken ct = default)
        where T : notnull
    {
        var item = await load();
        var classification = await classifier.ResolveAsync(item, ct);
        await audit.RecordAccessAsync(entityType, entityKey, action, classification, detail, ct);
        return item;
    }
}