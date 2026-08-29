using System.Text.Json;
using System.Text.Json.Serialization;

namespace ForgePoint.Auditing;

/// <summary>
/// Controlled vocabulary for the audit trail. Keep these stable - your SSP
/// narrative for 3.3.1 lists them, and changing a string silently orphans
/// historical rows from your reports.
/// </summary>
public static class AuditEventType
{
    public const string EntityChange     = "EntityChange";     // EF SaveChanges
    public const string DataAccess       = "DataAccess";       // read of technical data
    public const string Transfer         = "Transfer";         // download, DNC push, print, email
    public const string Authn            = "Authn";
    public const string Authz            = "Authz";            // permission change, access denial
    public const string Reclassification = "Reclassification"; // export determination changed
    public const string AuditRead        = "AuditRead";        // someone viewed the trail itself
    public const string Admin            = "Admin";
}

public static class AuditAction
{
    public const string Insert   = "Insert";
    public const string Update   = "Update";
    public const string Delete   = "Delete";
    public const string View     = "View";
    public const string Download = "Download";
    public const string Print    = "Print";
    public const string DncPush  = "DncPush";
    public const string Login    = "Login";
    public const string Logout   = "Logout";
    public const string Denied   = "Denied";
    public const string Query    = "Query";

    // Local Identity lifecycle. With an external IdP these live in the IdP's
    // logs; with local Identity they are yours to record.
    public const string LoginFailed    = "LoginFailed";
    public const string Lockout        = "Lockout";
    public const string PasswordChange = "PasswordChange";
    public const string PasswordReset  = "PasswordReset";
    public const string MfaEnroll      = "MfaEnroll";
    public const string MfaReset       = "MfaReset";
    public const string AccountCreate  = "AccountCreate";
    public const string AccountDisable = "AccountDisable";
    public const string RoleGrant      = "RoleGrant";
    public const string RoleRevoke     = "RoleRevoke";
}

public static class AuditOutcome
{
    public const string Success = "Success";
    public const string Failure = "Failure";
    public const string Denied  = "Denied";
}

public enum ActorKind
{
    User,
    Service,
    Machine,

    /// <summary>
    /// Pre-authentication. Only legitimate for failed logons and unknown-user
    /// attempts, where there is genuinely no principal to name. Everything
    /// post-authentication must be attributable (3.3.2).
    /// </summary>
    Anonymous
}

/// <summary>
/// One audit row, already redacted and already classified. The classification
/// is a snapshot: it records what the item's jurisdiction was at the moment of
/// the event, not a pointer that later resolves to something else.
/// </summary>
public sealed record AuditRecord
{
    public required string EventType { get; init; }
    public required string Action    { get; init; }
    public required string Outcome   { get; init; }

    public required string    ActorId   { get; init; }
    public required string    ActorName { get; init; }
    public required ActorKind ActorKind { get; init; }

    public string? ClientIp  { get; init; }
    public string? CircuitId { get; init; }
    public required Guid CorrelationId { get; init; }

    public string? EntityType { get; init; }
    public string? EntityKey  { get; init; }

    public ExportClassification Classification { get; init; } = ExportClassification.Undetermined;

    public string? Reason { get; init; }

    /// <summary>Serialised JSON. Already redacted.</summary>
    public string  DetailJson  { get; init; } = "{}";
    public string? ChangesJson { get; init; }
}

/// <summary>Property will never appear in the audit trail, in old or new value form.</summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class AuditRedactAttribute : Attribute;

/// <summary>
/// Whole entity is excluded from change auditing (cache tables, the audit
/// trail itself). Prefer this over silently not registering the type.
/// </summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class AuditExcludeAttribute : Attribute;

public static class AuditJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
        // No reference handling: the payload must be a flat, self-describing
        // snapshot that is still readable in five years without the CLR types.
    };

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
}