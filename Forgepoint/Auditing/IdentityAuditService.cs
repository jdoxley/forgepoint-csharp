namespace ForgePoint.Auditing;

/// <summary>
/// Identity lifecycle events. With an external IdP these live in the provider's
/// logs; with local ASP.NET Core Identity they are yours to record, and they
/// carry several scored requirements (3.1.8 failed logon attempts, 3.5.x
/// authenticator management, 3.1.1/3.1.2 account management).
///
/// Call these from your login endpoint and from thin wrappers around
/// UserManager. Do NOT rely on the EF interceptor picking up the AspNetUsers
/// row diff: "AccessFailedCount 2 -> 3" is not a usable audit record, and
/// UserManager writes through its own store anyway.
///
/// Note the actor/subject distinction. When an administrator resets someone
/// else's password, the actor is the administrator and the subject is the
/// account. Both must appear, or you cannot answer "who reset it".
/// </summary>
public sealed class IdentityAuditService(IAuditLogger audit)
{
    private const string UserEntity = "ApplicationUser";

    // ---------- Pre-authentication (no principal exists yet) ----------

    /// <summary>
    /// 3.1.8. Log the attempted identifier so repeated attempts against one
    /// account are visible.
    ///
    /// Caution: users routinely type a password into the username field. If
    /// that worries you, hash the attempted name before passing it here and
    /// correlate on the hash - you lose readability but keep the pattern.
    /// </summary>
    public Task LoginFailedAsync(
        string attemptedUserName, string? clientIp, string reason,
        CancellationToken ct = default)
        => audit.LogUnattributedAsync(new AuditRecordRequest(
                AuditEventType.Authn, AuditAction.LoginFailed, AuditOutcome.Failure)
            {
                EntityType = UserEntity,
                Detail = new { attempted = Truncate(attemptedUserName), reason }
            }, clientIp, ct);

    /// <summary>Account locked by the failed-attempt threshold. Alert-worthy.</summary>
    public Task LockedOutAsync(
        string attemptedUserName, string? clientIp, DateTimeOffset? lockoutEnd,
        CancellationToken ct = default)
        => audit.LogUnattributedAsync(new AuditRecordRequest(
                AuditEventType.Authn, AuditAction.Lockout, AuditOutcome.Denied)
            {
                EntityType = UserEntity,
                Detail = new { attempted = Truncate(attemptedUserName), lockoutEnd }
            }, clientIp, ct);

    // ---------- Post-authentication (actor is established) ----------

    public Task PasswordChangedAsync(
        string subjectUserId, string subjectUserName, bool selfService,
        CancellationToken ct = default)
        => audit.LogAsync(new AuditRecordRequest(
                AuditEventType.Authz,
                selfService ? AuditAction.PasswordChange : AuditAction.PasswordReset,
                AuditOutcome.Success)
            {
                EntityType     = UserEntity,
                EntityKey      = subjectUserId,
                Classification = ExportClassification.NotControlled,
                Detail = new { subject = subjectUserName, selfService }
            }, ct);

    public Task MfaChangedAsync(
        string subjectUserId, string subjectUserName, bool enrolled, string method,
        CancellationToken ct = default)
        => audit.LogAsync(new AuditRecordRequest(
                AuditEventType.Authz,
                enrolled ? AuditAction.MfaEnroll : AuditAction.MfaReset,
                AuditOutcome.Success)
            {
                EntityType     = UserEntity,
                EntityKey      = subjectUserId,
                Classification = ExportClassification.NotControlled,
                Detail = new { subject = subjectUserName, method }
            }, ct);

    /// <summary>
    /// Role changes are the highest-value rows in the whole trail. A grant of
    /// the audit-viewer role is what 3.3.9 asks you to be able to show.
    /// </summary>
    public Task RoleChangedAsync(
        string subjectUserId, string subjectUserName, string role, bool granted,
        string justification, CancellationToken ct = default)
        => audit.LogAsync(new AuditRecordRequest(
                AuditEventType.Authz,
                granted ? AuditAction.RoleGrant : AuditAction.RoleRevoke,
                AuditOutcome.Success)
            {
                EntityType     = UserEntity,
                EntityKey      = subjectUserId,
                Classification = ExportClassification.NotControlled,
                Reason         = justification,
                Detail = new { subject = subjectUserName, role }
            }, ct);

    public Task AccountCreatedAsync(
        string subjectUserId, string subjectUserName, CancellationToken ct = default)
        => audit.LogAsync(new AuditRecordRequest(
                AuditEventType.Authz, AuditAction.AccountCreate, AuditOutcome.Success)
            {
                EntityType     = UserEntity,
                EntityKey      = subjectUserId,
                Classification = ExportClassification.NotControlled,
                Detail = new { subject = subjectUserName }
            }, ct);

    /// <summary>
    /// Disable, never delete. actor_id on historical rows is a local database
    /// key; deleting the user row orphans five years of audit history.
    /// </summary>
    public Task AccountDisabledAsync(
        string subjectUserId, string subjectUserName, string justification,
        CancellationToken ct = default)
        => audit.LogAsync(new AuditRecordRequest(
                AuditEventType.Authz, AuditAction.AccountDisable, AuditOutcome.Success)
            {
                EntityType     = UserEntity,
                EntityKey      = subjectUserId,
                Classification = ExportClassification.NotControlled,
                Reason         = justification,
                Detail = new { subject = subjectUserName }
            }, ct);

    private static string Truncate(string value) =>
        value.Length <= 128 ? value : value[..128];
}