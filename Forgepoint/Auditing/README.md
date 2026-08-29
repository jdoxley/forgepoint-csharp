# ForgePoint audit trail

EF Core + Postgres + Blazor Server. Built for CMMC Level 2 (NIST SP 800-171 Rev 2, AU family) with ITAR technical-data access logging.

## Packages

```
dotnet add package Audit.EntityFramework.Core
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL
```

Audit.NET is used **only** for change capture — resolving database-generated keys after insert and computing per-column diffs. Persistence, transaction ownership, redaction, and everything non-EF is in this folder.

## Files

| File | Purpose |
|---|---|
| `sql/001_audit_schema.sql` | Table, hash chain, append-only triggers, roles, partitions |
| `sql/002_export_classification.sql` | Per-item classification columns, versioned hash payload, exposure review |
| `sql/003_application_grants.sql` | Business-schema grants, migrator role |
| `Auditing/AuditRecord.cs` | Event vocabulary, redaction attributes |
| `Auditing/ExportClassification.cs` | Per-item jurisdiction model, resolver, reclassification |
| `Auditing/CurrentUser.cs` | Circuit-scoped identity, named service principals |
| `Auditing/AuditWriter.cs` | Raw Postgres insert, fail-closed, alerting |
| `Auditing/AuditableDbContext.cs` | Save coordinator, both context bases, event mapping |
| `Auditing/AuditTypeRegistry.cs` | Per-type rules for framework classes you can't attribute |
| `Auditing/IdentityAuditService.cs` | Local Identity lifecycle: logons, lockouts, roles, MFA |
| `Auditing/AuditingDbContextFactory.cs` | Scoped factory that injects circuit identity |
| `Auditing/AuditLogger.cs` | Explicit events: reads, transfers, auth, denials |
| `Auditing/AuditQueryService.cs` | Reduction/reporting + chain verification |
| `Auditing/AuditServiceCollectionExtensions.cs` | DI wiring, IP capture, nightly verify |

## Wiring

Run the SQL as a DBA role — **not** as the application role. If the app owns the objects it can drop the triggers that enforce append-only.

```csharp
builder.Services.AddHttpContextAccessor();
builder.Services.AddForgePointAuditing<AppDbContext>(builder.Configuration);
```

Run `001`, `002`, and `003` in order.

Put the IP-capture component above the router in `Routes.razor`:

```razor
<AuditSessionInitializer />
<Router AppAssembly="@typeof(Program).Assembly">...</Router>
```

Your context:

```csharp
public sealed class AppDbContext(
    DbContextOptions<AppDbContext> options, AuditSaveCoordinator coordinator)
    : AuditableDbContext(options, coordinator)
{
    public DbSet<WorkOrder> WorkOrders => Set<WorkOrder>();
    public DbSet<NcProgram> Programs   => Set<NcProgram>();
}
```

### If the context must also be an IdentityDbContext

`AuditDbContext` and `IdentityDbContext` are both classes, so you can't inherit
both. Use the Identity base and register the framework types, because
`[AuditRedact]` only works on classes you own:

```csharp
public sealed class AppDbContext(
    DbContextOptions<AppDbContext> options, AuditSaveCoordinator coordinator)
    : AuditableIdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>(options, coordinator)
{
    public DbSet<WorkOrder> WorkOrders => Set<WorkOrder>();
}
```

```csharp
builder.Services.AddForgePointAuditing<AppDbContext>(builder.Configuration, types =>
{
    types.WithIdentityDefaults<ApplicationUser, Guid>();
    types.ForType<ApplicationUser>().Redact("BadgeNumber");   // your own additions
});
```

`WithIdentityDefaults` redacts `PasswordHash`, `SecurityStamp`,
`ConcurrencyStamp`, token values, and external provider keys, and marks the
Identity types as carrying no technical data so they don't land in your
"needs export determination" queue. Rules inherit down the type hierarchy, so
configuring `IdentityUser` covers `ApplicationUser : IdentityUser`.

Splitting Identity into a separate context is also viable, but with local
Identity it buys less than it would behind an external IdP — the Identity
tables are your authentication system of record either way, and a separate
context means user administration can't share a transaction with the business
change that motivated it.

## Local Identity

The EF interceptor will pick up `AspNetUsers` row diffs, but
`"AccessFailedCount 2 -> 3"` is not a usable audit record, and `UserManager`
writes through its own store. Log these explicitly instead:

```csharp
// In your login endpoint - HttpContext is available here, no circuit yet
var result = await _signIn.PasswordSignInAsync(userName, password, remember, true);

if (result.IsLockedOut)
    await _identityAudit.LockedOutAsync(userName, ip, lockoutEnd);
else if (!result.Succeeded)
    await _identityAudit.LoginFailedAsync(userName, ip, "invalid credentials");
// success is logged by AuditCircuitHandler when the circuit opens
```

`LoginFailedAsync` and `LockedOutAsync` go through `LogUnattributedAsync`,
which writes `actor_kind = 'Anonymous'`. That is the only legitimate use of it —
a failed logon genuinely has no principal. Don't reach for it to silence an
`UnattributedActionException` on an authenticated path.

Administrative actions carry both actor and subject, since "who reset this
password" is the question:

```csharp
await _identityAudit.RoleChangedAsync(user.Id, user.UserName, "AuditViewer",
    granted: true, justification: "Quality manager, per SSP 3.3.9");
```

**Never hard-delete a user.** `actor_id` is a local database key, so deleting
the row orphans five years of history. Disable instead — `AccountDisabledAsync`
records it. `actor_name` is denormalised onto every audit row as a hedge, but
the key is what your reports join on.

### Controls that were the IdP's problem and are now yours

Not code in this folder, but they show up in the same assessment:

- **3.5.3 MFA.** Required for privileged accounts, and this is scored. ASP.NET
  Core Identity has TOTP authenticator support built in; it is not on by
  default. `MfaChangedAsync` logs enrolment and reset.
- **3.1.8 limit unsuccessful logon attempts.** Identity lockout, explicitly
  configured — `MaxFailedAccessAttempts`, `DefaultLockoutTimeSpan`.
- **3.5.7–3.5.11** password complexity, reuse, and temporary-password rules.
  Identity's `PasswordOptions` covers some; reuse history needs a custom
  `IPasswordValidator`.
- **3.1.10/3.1.11 session lock and termination.** Blazor circuits outlive an
  idle browser tab; set an inactivity timeout that ends the circuit.
- **3.5.5 identifier reuse.** Never reissue a retired username — it would make
  historical `actor_name` values ambiguous.
- **3.13.11 FIPS-validated crypto.** Identity's PBKDF2 hasher resolves to the
  OS provider; on Windows enable FIPS mode, on Linux use a FIPS OpenSSL build.

## Using it

**Entity changes** need nothing — they're captured on `SaveChangesAsync`. Wrap a user action to group its writes under one correlation ID:

```csharp
using var _ = _user.BeginOperation();
await using var db = await _factory.CreateDbContextAsync();
// ...touch five tables...
await db.SaveChangesAsync(ct);   // five rows, one correlation_id
```

**Classification is per item, not per type.** The shop runs controlled and uncontrolled work through the same tables, so the resolver asks each instance.

The item that carries the determination implements `IExportClassified`:

```csharp
public sealed class Part : IExportClassified
{
    public string PartNumber { get; set; } = "";
    public ExportClassification ExportClassification { get; set; }
        = ExportClassification.Undetermined;
}
```

Everything downstream inherits — programs, setup sheets, operations, inspection records:

```csharp
public sealed class NcProgram : IExportDerived
{
    public int Id { get; set; }
    public string PartNumber { get; set; } = "";
    [AuditRedact] public string ApiToken { get; set; } = "";

    public (string Type, string Key) ClassificationSource => ("Part", PartNumber);
}
```

Types with genuinely no technical data are marked explicitly:

```csharp
[NoTechnicalData] public sealed class ShiftSchedule { ... }
```

A type that implements neither interface and lacks the attribute resolves to `Undetermined` and logs a one-time warning naming the type. That gives you a discoverable to-do list rather than a silent gap, and `Undetermined` is treated as controlled for handling while reporting separately.

You supply the store that reads your determinations table:

```csharp
public sealed class PartClassificationStore(IDbContextFactory<AppDbContext> f)
    : IExportClassificationStore
{
    public async Task<ExportClassification?> LoadAsync(
        string entityType, string entityKey, CancellationToken ct = default)
    {
        if (entityType != "Part") return null;
        await using var db = await f.CreateDbContextAsync(ct);
        return await db.Parts.Where(p => p.PartNumber == entityKey)
                             .Select(p => p.ExportClassification)
                             .FirstOrDefaultAsync(ct);
    }
}
```

Register it before `AddForgePointAuditing`, or the null store takes over and everything records as Undetermined.

**Reclassification** goes through `ReclassificationService`, never a direct write — it records the before/after pair, the authority, and the reference, then invalidates the cache:

```csharp
await _reclassify.RecordAsync("Part", "PN-4471",
    previous: ExportClassification.NotControlled,
    updated:  ExportClassification.Itar("XII(e)", "CJ-2026-0143", DateTime.UtcNow),
    authority: "CJ ruling", reference: "CJ-2026-0143",
    justification: "Customer flowdown updated on contract line 7");
```

Then run the exposure review, which is the query you'll actually be asked for:

```csharp
var exposure = await _auditQuery.ExposureReviewAsync("Part", "PN-4471");
```

It returns every actor who touched that item, when, how many times, which actions, and which jurisdictions were in force at the time — so you can see who saw it while it was mismarked.

**Controlled reads** — the ITAR-critical half. Nothing in EF sees these:

```csharp
var program = await _guard.ReleaseAsync(
    "NcProgram", id.ToString(), AuditAction.Download,
    () => _repo.GetProgramAsync(id));
```

If the audit write fails, `ReleaseAsync` throws and the data is never returned. That ordering is deliberate: an unlogged view by an unverified person is the deemed-export scenario. Non-controlled items still produce an access row — the negative evidence matters as much as the positive, and the classification snapshot is what proves the item wasn't controlled at the time.

**DNC pushes** are transfers of technical data to a machine:

```csharp
await _audit.LogAsync(new AuditRecordRequest(
    AuditEventType.Transfer, AuditAction.DncPush, AuditOutcome.Success)
{
    EntityType = "NcProgram",
    EntityKey  = program.Id.ToString(),
    Detail = new { control = "DVF5000", program = program.Name, revision = program.Revision }
    // Classification omitted: resolved from EntityType/EntityKey automatically
});
```

**Background work** must run as a named principal — a shared "system" identity fails 3.3.2 as thoroughly as an anonymous row:

```csharp
using var _ = ((CircuitCurrentUser)user).RunAs(SystemActors.DncGateway);
```

## Control mapping

| Requirement | Where |
|---|---|
| 3.3.1 log content | `AuditEventType` / `AuditAction` vocabulary — mirror this list in your SSP |
| 3.3.2 unique traceability | `CircuitCurrentUser.Id` throws rather than write an unattributed row; `SystemActors` |
| 3.3.4 alert on failure | `IAuditAlerter`, EventId 3304, plus transaction rollback |
| 3.3.5 correlation | `correlation_id` via `BeginOperation()`; `ByCorrelationAsync` |
| 3.3.6 reduction & reporting | `AuditQueryService` |
| 3.3.7 clock sync | `clock_timestamp()` server-side, `timestamptz`. NTP is an OS task — see below |
| 3.3.8 protect audit info | Append-only triggers, role split, hash chain, `AuditRead` events |
| 3.3.9 privileged management | Separate `forgepoint_auditor` connection; gate the viewer on its own role |

## Still yours to do

- **NTP.** 3.3.7 is an OS/infrastructure control. Point the host at an authoritative source and document it; nothing in this code can satisfy it.
- **No external telemetry.** Application Insights, Sentry, Datadog, any SaaS sink will carry CUI out of your boundary in exception payloads. On a local-network-only deployment this mostly means: check what your logging providers are actually configured to do.
- **Encryption at rest.** Postgres has no TDE. Use LUKS/BitLocker on the volume, or `pgcrypto` on the `detail` column if you need column-level. `hostssl` + `scram-sha-256` in `pg_hba.conf` even on the LAN.
- **The audit viewer UI**, gated on a dedicated role, with role-membership changes themselves audited.
- **Reason-for-change prompts** on edits to released technical data — a UI concern; the `Reason` column is already there.
- **Retention.** ITAR is five years. Partitions are monthly; write the detach-to-offline-media job and prove restores work.
- **Backups are CUI too.** Same encryption, same access control, same US-person restriction.

## Two things to verify against your package version

1. `EventEntry.Entity` must be populated even with `IncludeEntityObjects(false)` — the flag controls serialisation, not capture, and the classification resolver depends on it. Verify with one test; if your version clears it, resolve by `(EntityType, PrimaryKey)` instead.
2. `EntityFrameworkEvent.Result` in `AuditableDbContext.SaveChangesAsync` — the property has moved between Audit.EntityFramework versions. If it doesn't compile, the row count is also derivable from the entry count.
3. `AuditDataProvider` vs `IAuditDataProvider` — recent releases introduced the interface. The abstract class assignment used here works on both, but check the deprecation warnings.

None is load-bearing for the design.