using System.Data;
using System.Data.Common;
using System.Net;
using Npgsql;
using NpgsqlTypes;

namespace ForgePoint.Auditing;

/// <summary>
/// Raised when an audit row could not be persisted. Callers must treat this as
/// a hard failure: roll the business transaction back, or deny the read.
/// </summary>
public sealed class AuditWriteException(string message, Exception? inner = null)
    : Exception(message, inner);

/// <summary>
/// 3.3.4 - alert on audit logging process failure. Rolling back is not enough;
/// somebody has to find out. Wire this to whatever the shop actually watches.
/// </summary>
public interface IAuditAlerter
{
    Task AuditFailureAsync(string context, Exception error, CancellationToken ct = default);
}

public sealed class LoggingAuditAlerter(ILogger<LoggingAuditAlerter> log) : IAuditAlerter
{
    public Task AuditFailureAsync(string context, Exception error, CancellationToken ct = default)
    {
        // EventId 3304 => alert rule in your log pipeline. Keep this inside the
        // boundary: no SaaS sinks, the message can contain CUI context.
        log.LogCritical(new EventId(3304, "AuditLoggingFailure"), error,
            "AUDIT LOGGING FAILURE: {Context}. Operation was rolled back.", context);
        return Task.CompletedTask;
    }
}

/// <summary>
/// Writes audit rows. Deliberately raw SQL rather than EF: this must not go
/// through a ChangeTracker that is itself being audited, and it must be able
/// to enlist in a transaction owned by someone else.
/// </summary>
public sealed class AuditWriter(IAuditAlerter alerter, ILogger<AuditWriter> log)
{
    private const string InsertSql = """
        INSERT INTO audit.audit_trail
            (event_type, action, outcome,
             actor_id, actor_name, actor_kind,
             client_ip, circuit_id, correlation_id,
             entity_type, entity_key,
             jurisdiction, usml_category, eccn, determination_id, classified_utc,
             reason,
             detail, changes)
        VALUES
            (@event_type, @action, @outcome,
             @actor_id, @actor_name, @actor_kind,
             @client_ip, @circuit_id, @correlation_id,
             @entity_type, @entity_key,
             @jurisdiction, @usml_category, @eccn, @determination_id, @classified_utc,
             @reason,
             @detail, @changes)
        """;

    /// <summary>
    /// Insert on an existing connection, optionally inside an existing transaction.
    /// Used by AuditableDbContext so audit rows commit or roll back with the data.
    /// </summary>
    public async Task WriteAsync(
        DbConnection connection,
        DbTransaction? transaction,
        IReadOnlyList<AuditRecord> records,
        string context,
        CancellationToken ct = default)
    {
        if (records.Count == 0) return;

        try
        {
            var npg = (NpgsqlConnection)connection;
            if (npg.State != ConnectionState.Open)
                await npg.OpenAsync(ct);

            await using var batch = new NpgsqlBatch(npg, (NpgsqlTransaction?)transaction);
            foreach (var r in records)
                batch.BatchCommands.Add(BuildCommand(r));

            var written = await batch.ExecuteNonQueryAsync(ct);
            if (written < records.Count)
                throw new AuditWriteException(
                    $"Expected {records.Count} audit rows, database reported {written}.");
        }
        catch (Exception ex) when (ex is not AuditWriteException)
        {
            await alerter.AuditFailureAsync(context, ex, CancellationToken.None);
            throw new AuditWriteException($"Audit write failed ({context}).", ex);
        }
        catch (AuditWriteException ex)
        {
            await alerter.AuditFailureAsync(context, ex, CancellationToken.None);
            throw;
        }
    }

    /// <summary>
    /// Standalone write on its own connection, for events with no surrounding
    /// business transaction (logins, reads, downloads, DNC pushes).
    /// </summary>
    public async Task WriteAsync(
        NpgsqlDataSource dataSource,
        IReadOnlyList<AuditRecord> records,
        string context,
        CancellationToken ct = default)
    {
        if (records.Count == 0) return;

        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await WriteAsync(conn, null, records, context, ct);
    }

    private static NpgsqlBatchCommand BuildCommand(AuditRecord r)
    {
        var cmd = new NpgsqlBatchCommand(InsertSql);
        var p = cmd.Parameters;

        p.AddWithValue("event_type",     NpgsqlDbType.Text, r.EventType);
        p.AddWithValue("action",         NpgsqlDbType.Text, r.Action);
        p.AddWithValue("outcome",        NpgsqlDbType.Text, r.Outcome);
        p.AddWithValue("actor_id",       NpgsqlDbType.Text, r.ActorId);
        p.AddWithValue("actor_name",     NpgsqlDbType.Text, r.ActorName);
        p.AddWithValue("actor_kind",     NpgsqlDbType.Text, r.ActorKind.ToString());
        p.AddWithValue("client_ip",      NpgsqlDbType.Inet, ParseIp(r.ClientIp));
        p.AddWithValue("circuit_id",     NpgsqlDbType.Text, (object?)r.CircuitId ?? DBNull.Value);
        p.AddWithValue("correlation_id", NpgsqlDbType.Uuid, r.CorrelationId);
        p.AddWithValue("entity_type",    NpgsqlDbType.Text, (object?)r.EntityType ?? DBNull.Value);
        p.AddWithValue("entity_key",     NpgsqlDbType.Text, (object?)r.EntityKey ?? DBNull.Value);
        p.AddWithValue("jurisdiction",     NpgsqlDbType.Text, r.Classification.Jurisdiction.ToString());
        p.AddWithValue("usml_category",    NpgsqlDbType.Text, (object?)r.Classification.UsmlCategory ?? DBNull.Value);
        p.AddWithValue("eccn",             NpgsqlDbType.Text, (object?)r.Classification.Eccn ?? DBNull.Value);
        p.AddWithValue("determination_id", NpgsqlDbType.Text, (object?)r.Classification.DeterminationId ?? DBNull.Value);
        p.AddWithValue("classified_utc",   NpgsqlDbType.TimestampTz,
            r.Classification.ClassifiedUtc is { } c
                ? DateTime.SpecifyKind(c, DateTimeKind.Utc)
                : (object)DBNull.Value);
        p.AddWithValue("reason",         NpgsqlDbType.Text, (object?)r.Reason ?? DBNull.Value);
        p.AddWithValue("detail",         NpgsqlDbType.Jsonb, r.DetailJson);
        p.AddWithValue("changes",        NpgsqlDbType.Jsonb, (object?)r.ChangesJson ?? DBNull.Value);

        return cmd;
    }

    private static object ParseIp(string? value) =>
        IPAddress.TryParse(value, out var ip) ? ip : DBNull.Value;
}
