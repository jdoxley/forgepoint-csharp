using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.Circuits;

namespace ForgePoint.Auditing;

/// <summary>
/// Who is acting. Scoped to the Blazor circuit, NOT to an HTTP request -
/// IHttpContextAccessor is null or stale once the SignalR connection takes over.
/// </summary>
public interface ICurrentUser
{
    string    Id        { get; }
    string    Name      { get; }
    ActorKind Kind      { get; }
    string?   ClientIp  { get; }
    string?   CircuitId { get; }

    /// <summary>New per user-initiated operation. Ties an N-table write to one action (3.3.5).</summary>
    Guid CorrelationId { get; }

    bool IsEstablished { get; }

    /// <summary>Start a new correlation scope. Call at the top of a command handler.</summary>
    IDisposable BeginOperation();
}

/// <summary>
/// 3.3.2 requires every audited action to trace to a single individual.
/// An unattributed row is an assessment finding, so we refuse to write one.
/// Background work must run under a named service principal (see SystemActors).
/// </summary>
public sealed class UnattributedActionException(string message) : InvalidOperationException(message);

public sealed class CircuitCurrentUser : ICurrentUser
{
    private readonly AsyncLocal<Guid?> _operationId = new();

    private string?   _id;
    private string?   _name;
    private ActorKind _kind = ActorKind.User;

    public string Id => _id ?? throw new UnattributedActionException(
        "No authenticated principal on this circuit. Wrap background or machine-initiated " +
        "work in ICurrentUserScope.RunAs(SystemActors.X) so the action is attributable.");

    public string    Name      => _name ?? Id;
    public ActorKind Kind      => _kind;
    public string?   ClientIp  { get; internal set; }
    public string?   CircuitId { get; internal set; }

    public Guid CorrelationId => _operationId.Value ??= Guid.NewGuid();

    public bool IsEstablished => _id is not null;

    public IDisposable BeginOperation()
    {
        var previous = _operationId.Value;
        _operationId.Value = Guid.NewGuid();
        return new Restore(() => _operationId.Value = previous);
    }

    internal void Set(string id, string name, ActorKind kind)
    {
        _id = id; _name = name; _kind = kind;
    }

    internal void Clear() { _id = null; _name = null; }

    /// <summary>
    /// Impersonate a named non-human principal for the duration of a scope.
    /// Used by hosted services, the Halter cell integration, DNC pushes, etc.
    /// </summary>
    public IDisposable RunAs(ServicePrincipal principal)
    {
        var (pid, pname, pkind) = (_id, _name, _kind);
        Set(principal.Id, principal.Name, principal.Kind);
        return new Restore(() =>
        {
            _id = pid; _name = pname; _kind = pkind;
        });
    }

    private sealed class Restore(Action action) : IDisposable
    {
        public void Dispose() => action();
    }
}

public sealed record ServicePrincipal(string Id, string Name, ActorKind Kind);

/// <summary>
/// Named principals for non-interactive work. Each background job gets its own -
/// a shared "system" identity defeats 3.3.2 just as thoroughly as an anonymous row.
/// </summary>
public static class SystemActors
{
    public static readonly ServicePrincipal Scheduler =
        new("svc:scheduler", "ForgePoint Scheduler", ActorKind.Service);

    public static readonly ServicePrincipal DncGateway =
        new("svc:dnc-gateway", "DNC Gateway", ActorKind.Service);

    public static readonly ServicePrincipal RobotCell =
        new("svc:halter-cell", "Halter LoadAssistant Cell", ActorKind.Machine);

    public static readonly ServicePrincipal Migration =
        new("svc:migration", "Schema Migration", ActorKind.Service);
}

/// <summary>
/// Populates the circuit-scoped identity when the circuit opens, and keeps it
/// current if the user re-authenticates mid-circuit.
/// </summary>
public sealed class AuditCircuitHandler : CircuitHandler, IDisposable
{
    private readonly CircuitCurrentUser _user;
    private readonly AuthenticationStateProvider _auth;
    private readonly IAuditLogger _audit;
    private readonly ILogger<AuditCircuitHandler> _log;

    public AuditCircuitHandler(
        ICurrentUser user,
        AuthenticationStateProvider auth,
        IAuditLogger audit,
        ILogger<AuditCircuitHandler> log)
    {
        _user = (CircuitCurrentUser)user;
        _auth = auth;
        _audit = audit;
        _log = log;
        _auth.AuthenticationStateChanged += OnAuthStateChanged;
    }

    public override async Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken ct)
    {
        _user.CircuitId = circuit.Id;
        var state = await _auth.GetAuthenticationStateAsync();
        Apply(state.User);

        if (_user.IsEstablished)
            await _audit.LogAsync(new AuditRecordRequest(
                AuditEventType.Authn, AuditAction.Login, AuditOutcome.Success)
            {
                Detail = new { circuit = circuit.Id },
                Classification = ExportClassification.NotControlled
            }, ct);
    }

    public override async Task OnCircuitClosedAsync(Circuit circuit, CancellationToken ct)
    {
        if (!_user.IsEstablished) return;

        await _audit.LogAsync(new AuditRecordRequest(
            AuditEventType.Authn, AuditAction.Logout, AuditOutcome.Success)
        {
            Detail = new { circuit = circuit.Id, reason = "circuit closed" },
            Classification = ExportClassification.NotControlled
        }, ct);
    }

    private void OnAuthStateChanged(Task<AuthenticationState> task) => _ = Track(task);

    private async Task Track(Task<AuthenticationState> task)
    {
        try { Apply((await task).User); }
        catch (Exception ex) { _log.LogError(ex, "Failed to refresh audit identity"); }
    }

    private void Apply(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true) { _user.Clear(); return; }

        // Local ASP.NET Core Identity puts the user's primary key in
        // NameIdentifier and the user name in Name. The other lookups are
        // fallbacks in case you ever add an external IdP alongside.
        var id = principal.FindFirstValue(ClaimTypes.NameIdentifier)
              ?? principal.FindFirstValue("sub")
              ?? principal.FindFirstValue(ClaimTypes.PrimarySid);

        var name = principal.FindFirstValue(ClaimTypes.Name)
                ?? principal.FindFirstValue("preferred_username")
                ?? principal.Identity.Name;

        // actor_id is a local database key, so it only means anything while
        // the user row survives. Never hard-delete a user: disable instead, or
        // five-year-old audit rows point at nothing. actor_name is
        // denormalised onto every row for exactly this reason.

        if (id is null || name is null)
        {
            // Fail closed rather than write an unattributable row.
            _log.LogError("Authenticated principal has no stable identifier; audit disabled for this circuit");
            _user.Clear();
            return;
        }

        _user.Set(id, name, ActorKind.User);
    }

    public void Dispose() => _auth.AuthenticationStateChanged -= OnAuthStateChanged;
}