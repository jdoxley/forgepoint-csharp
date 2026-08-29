using System.Text;
using Npgsql;

namespace ForgePoint.Auditing;

public sealed record AuditTrailEntry
{
    public long     Id            { get; init; }
    public DateTime OccurredUtc   { get; init; }
    public string   EventType     { get; init; } = "";
    public string   Action        { get; init; } = "";
    public string   Outcome       { get; init; } = "";
    public string   ActorId       { get; init; } = "";
    public string   ActorName     { get; init; } = "";
    public string   ActorKind     { get; init; } = "";
    public string?  ClientIp      { get; init; }
    public Guid     CorrelationId { get; init; }
    public string?  EntityType    { get; init; }
    public string?  EntityKey     { get; init; }
    public string   Jurisdiction    { get; init; } = "";
    public string?  UsmlCategory    { get; init; }
    public string?  Eccn            { get; init; }
    public string?  DeterminationId { get; init; }
    public string?  Reason          { get; init; }
    public string   DetailJson    { get; init; } = "{}";
    public string?  ChangesJson   { get; init; }
}

public sealed record AuditQuery
{
    public DateTime? From          { get; init; }
    public DateTime? To            { get; init; }
    public string?   ActorId       { get; init; }
    public string?   EventType     { get; init; }
    public string?   Action        { get; init; }
    public string?   EntityType    { get; init; }
    public string?   EntityKey     { get; init; }
    public Guid?     CorrelationId { get; init; }
    public string?   Jurisdiction  { get; init; }
    /// <summary>Only rows for items that were controlled at the time of the event.</summary>
    public bool      ControlledOnly { get; init; }
    public int       Take          { get; init; } = 200;
    public long?     BeforeId      { get; init; }   // keyset pagination
}

public sealed record ChainVerification(bool Intact, long? FirstBadId, string? Reason);

public sealed record ExposureRow(
    string ActorId, string ActorName, string ActorKind,
    DateTime FirstTouch, DateTime LastTouch, long TouchCount,
    string[] Actions, string[] Jurisdictions);

/// <summary>
/// 3.3.6 - audit record reduction and report generation.
///
/// Connects with the auditor role (SELECT only) rather than the application
/// role, so a compromised app path cannot read history, and the viewer cannot
/// write it. Every query against this service is itself audited (3.3.8): the
/// people who can see the trail are the people most worth watching.
/// </summary>
public sealed class AuditQueryService(
    [FromKeyedServices(AuditServiceKeys.AuditorDataSource)] NpgsqlDataSource dataSource,
    IAuditLogger audit)
{
    public async Task<IReadOnlyList<AuditTrailEntry>> QueryAsync(
        AuditQuery query, CancellationToken ct = default)
    {
        await audit.LogAsync(new AuditRecordRequest(
            AuditEventType.AuditRead, AuditAction.Query, AuditOutcome.Success)
        {
            Detail = query,
            Classification = ExportClassification.Undetermined
        }, ct);

        var sql = new StringBuilder("""
            SELECT id, occurred_utc, event_type, action, outcome,
                   actor_id, actor_name, actor_kind, host(client_ip) AS client_ip,
                   correlation_id, entity_type, entity_key,
                   jurisdiction, usml_category, eccn, determination_id, reason,
                   detail::text, changes::text
              FROM audit.audit_trail
             WHERE 1 = 1
            """);

        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();

        void Filter(string clause, string name, object? value)
        {
            if (value is null) return;
            sql.Append(clause);
            cmd.Parameters.AddWithValue(name, value);
        }

        Filter(" AND occurred_utc >= @from",   "from",   query.From);
        Filter(" AND occurred_utc <  @to",     "to",     query.To);
        Filter(" AND actor_id = @actor",       "actor",  query.ActorId);
        Filter(" AND event_type = @etype",     "etype",  query.EventType);
        Filter(" AND action = @action",        "action", query.Action);
        Filter(" AND entity_type = @entity",   "entity", query.EntityType);
        Filter(" AND entity_key = @key",       "key",    query.EntityKey);
        Filter(" AND correlation_id = @corr",  "corr",   query.CorrelationId);
        Filter(" AND jurisdiction = @juris",   "juris",  query.Jurisdiction);
        Filter(" AND id < @before",            "before", query.BeforeId);

        if (query.ControlledOnly)
            sql.Append(" AND jurisdiction IN ('Itar', 'Ear', 'Undetermined')");

        sql.Append(" ORDER BY id DESC LIMIT @take");
        cmd.Parameters.AddWithValue("take", Math.Clamp(query.Take, 1, 1000));
        cmd.CommandText = sql.ToString();

        var results = new List<AuditTrailEntry>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            results.Add(new AuditTrailEntry
            {
                Id            = reader.GetInt64(0),
                OccurredUtc   = reader.GetDateTime(1),
                EventType     = reader.GetString(2),
                Action        = reader.GetString(3),
                Outcome       = reader.GetString(4),
                ActorId       = reader.GetString(5),
                ActorName     = reader.GetString(6),
                ActorKind     = reader.GetString(7),
                ClientIp      = reader.IsDBNull(8) ? null : reader.GetString(8),
                CorrelationId = reader.GetGuid(9),
                EntityType    = reader.IsDBNull(10) ? null : reader.GetString(10),
                EntityKey       = reader.IsDBNull(11) ? null : reader.GetString(11),
                Jurisdiction    = reader.GetString(12),
                UsmlCategory    = reader.IsDBNull(13) ? null : reader.GetString(13),
                Eccn            = reader.IsDBNull(14) ? null : reader.GetString(14),
                DeterminationId = reader.IsDBNull(15) ? null : reader.GetString(15),
                Reason          = reader.IsDBNull(16) ? null : reader.GetString(16),
                DetailJson      = reader.GetString(17),
                ChangesJson     = reader.IsDBNull(18) ? null : reader.GetString(18)
            });
        }

        return results;
    }

    /// <summary>
    /// Everything one user action did, across every table it touched.
    /// This is the view an investigator actually wants.
    /// </summary>
    public Task<IReadOnlyList<AuditTrailEntry>> ByCorrelationAsync(
        Guid correlationId, CancellationToken ct = default)
        => QueryAsync(new AuditQuery { CorrelationId = correlationId, Take = 1000 }, ct);

    /// <summary>
    /// Deemed-export review: who touched this piece of technical data, and how.
    /// Run this against a part number before responding to an export inquiry.
    /// </summary>
    public Task<IReadOnlyList<AuditTrailEntry>> AccessHistoryAsync(
        string entityType, string entityKey, CancellationToken ct = default)
        => QueryAsync(new AuditQuery
        {
            EntityType = entityType,
            EntityKey  = entityKey,
            Take       = 1000
        }, ct);

    /// <summary>
    /// Who touched this item, and under what classification, since a given
    /// point. Run after any upward reclassification: if the item was seen by
    /// someone not cleared for its new jurisdiction while it was mismarked,
    /// that is a potential unauthorised export and a disclosure decision.
    /// </summary>
    public async Task<IReadOnlyList<ExposureRow>> ExposureReviewAsync(
        string entityType, string entityKey, DateTime? since = null,
        CancellationToken ct = default)
    {
        await audit.LogAsync(new AuditRecordRequest(
            AuditEventType.AuditRead, AuditAction.Query, AuditOutcome.Success)
        {
            EntityType = entityType,
            EntityKey  = entityKey,
            Detail     = new { review = "exposure", since }
        }, ct);

        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT actor_id, actor_name, actor_kind, first_touch, last_touch,
                   touch_count, actions, jurisdictions
              FROM audit.exposure_review(@type, @key, @since)
            """;
        cmd.Parameters.AddWithValue("type", entityType);
        cmd.Parameters.AddWithValue("key", entityKey);
        cmd.Parameters.AddWithValue("since",
            since is { } d ? DateTime.SpecifyKind(d, DateTimeKind.Utc) : DateTime.MinValue.ToUniversalTime());

        var rows = new List<ExposureRow>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(new ExposureRow(
                reader.GetString(0), reader.GetString(1), reader.GetString(2),
                reader.GetDateTime(3), reader.GetDateTime(4), reader.GetInt64(5),
                reader.GetFieldValue<string[]>(6), reader.GetFieldValue<string[]>(7)));
        }
        return rows;
    }

    /// <summary>Nightly job should call this and alert on Intact == false.</summary>
    public async Task<ChainVerification> VerifyChainAsync(
        long fromId = 0, long toId = long.MaxValue, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT first_bad_id, reason FROM audit.verify_chain(@from, @to)";
        cmd.Parameters.AddWithValue("from", fromId);
        cmd.Parameters.AddWithValue("to", toId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return new ChainVerification(true, null, null);

        return new ChainVerification(false, reader.GetInt64(0), reader.GetString(1));
    }
}
