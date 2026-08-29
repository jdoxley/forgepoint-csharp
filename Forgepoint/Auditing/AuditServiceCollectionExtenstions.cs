using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;

namespace ForgePoint.Auditing;

public static class AuditServiceKeys
{
    public const string AppDataSource     = "audit:app";      // INSERT only
    public const string AuditorDataSource = "audit:auditor";  // SELECT only
}

public static class AuditServiceCollectionExtensions
{
    /// <summary>
    /// appsettings:
    ///   ConnectionStrings:ForgePoint        -> forgepoint_app role
    ///   ConnectionStrings:ForgePointAuditor -> forgepoint_auditor role
    ///
    /// Two roles, two connection strings. The app cannot read the trail; the
    /// viewer cannot write it (3.3.8/3.3.9). Keep both credentials in the shop's
    /// secret store, not in appsettings.json.
    /// </summary>
    public static IServiceCollection AddForgePointAuditing<TContext>(
        this IServiceCollection services,
        IConfiguration config,
        Action<AuditTypeRegistry>? configureTypes = null)
        where TContext : DbContext, IAuditableContext
    {
        // Built eagerly, at startup. A bad connection string must stop the
        // application booting - not surface on the first user's circuit, which
        // is what a lazy DI factory would do.
        var appDataSource     = PostgresConnectionString.CreateDataSource(config, "ForgePoint");
        var auditorDataSource = PostgresConnectionString.CreateDataSource(config, "ForgePointAuditor");

        services.AddKeyedSingleton(AuditServiceKeys.AppDataSource, appDataSource);
        services.AddKeyedSingleton(AuditServiceKeys.AuditorDataSource, auditorDataSource);

        // Options are singleton; the factory that consumes them is scoped.
        services.AddSingleton(new DbContextOptionsBuilder<TContext>()
            .UseNpgsql(appDataSource)
            .Options);

        services.AddSingleton<IAuditAlerter, LoggingAuditAlerter>();
        services.AddSingleton<AuditWriter>();
        services.AddMemoryCache();

        // Classification is per item, so the resolver needs a store that knows
        // where your determinations live. Register your implementation before
        // calling AddForgePointAuditing, or replace this line.
        services.TryAddScoped<IExportClassificationStore, NullExportClassificationStore>();
        services.AddScoped<IExportClassificationResolver, ExportClassificationResolver>();
        services.AddScoped<ReclassificationService>();
        services.AddScoped<EfEventMapper>();
        services.AddScoped<AuditSaveCoordinator>();

        // Per-type rules for framework classes you cannot decorate.
        var registry = new AuditTypeRegistry();
        configureTypes?.Invoke(registry);
        services.AddSingleton(registry);

        // Circuit-scoped identity. One instance per circuit, not per request.
        services.AddScoped<ICurrentUser, CircuitCurrentUser>();
        services.AddScoped<CircuitHandler, AuditCircuitHandler>();

        services.AddScoped<IAuditLogger, AuditLogger>();
        services.AddScoped<ControlledDataGuard>();
        services.AddScoped<IdentityAuditService>();
        services.AddScoped<AuditQueryService>();
        services.AddScoped<IDbContextFactory<TContext>, AuditingDbContextFactory<TContext>>();

        services.AddHostedService<AuditChainVerificationService>();

        // Audit.NET: opt-out means new entities are audited by default. On a
        // controlled system, forgetting to register a table must fail safe.
        Audit.EntityFramework.Configuration.Setup()
            .ForContext<TContext>(cfg => cfg
                .IncludeEntityObjects(false)
                .ExcludeValidationResults(true))
            .UseOptOut();

        Audit.Core.Configuration.AuditDisabled = false;
        Audit.Core.Configuration.IncludeStackTrace = false;  // stack frames can leak paths

        return services;
    }
}

/// <summary>
/// Placeholder store. Every item resolves to Undetermined, which is safe but
/// useless - replace with one that reads your determinations table.
/// </summary>
public sealed class NullExportClassificationStore(ILogger<NullExportClassificationStore> log)
    : IExportClassificationStore
{
    private bool _warned;

    public Task<ExportClassification?> LoadAsync(
        string entityType, string entityKey, CancellationToken ct = default)
    {
        if (!_warned)
        {
            _warned = true;
            log.LogWarning(
                "No IExportClassificationStore registered. All items will be recorded as " +
                "Undetermined. Register a real store before this system handles CUI.");
        }
        return Task.FromResult<ExportClassification?>(ExportClassification.Undetermined);
    }
}

/// <summary>
/// Client IP does not survive the jump from the initial HTTP render to the
/// SignalR circuit - they are different DI scopes. PersistentComponentState is
/// the supported way across that boundary.
///
/// Put &lt;AuditSessionInitializer /&gt; in Routes.razor / App.razor above the router.
/// </summary>
public sealed class AuditSessionInitializer : ComponentBase, IDisposable
{
    private const string Key = "audit:clientip";
    private PersistingComponentStateSubscription _subscription;

    [Inject] public PersistentComponentState State { get; set; } = default!;
    [Inject] public ICurrentUser User { get; set; } = default!;
    [Inject] public IHttpContextAccessor HttpContextAccessor { get; set; } = default!;

    protected override void OnInitialized()
    {
        var user = (CircuitCurrentUser)User;

        if (State.TryTakeFromJson<string>(Key, out var ip) && ip is not null)
        {
            // Interactive render: pick up what the server render persisted.
            user.ClientIp = ip;
            return;
        }

        // Static server render: HttpContext is available here and only here.
        var remote = HttpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
        user.ClientIp = remote;

        _subscription = State.RegisterOnPersisting(() =>
        {
            State.PersistAsJson(Key, remote);
            return Task.CompletedTask;
        });
    }

    public void Dispose() => _subscription.Dispose();
}

/// <summary>
/// Nightly hash-chain verification. A break means either corruption or someone
/// with database-owner rights editing history; both are incidents.
/// </summary>
public sealed class AuditChainVerificationService(
    IServiceScopeFactory scopes,
    IAuditAlerter alerter,
    ILogger<AuditChainVerificationService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var now = DateTimeOffset.UtcNow;
            var next = now.Date.AddDays(1).AddHours(3);   // 03:00 UTC
            await Task.Delay(next - now, ct);

            try
            {
                using var scope = scopes.CreateScope();
                var user = (CircuitCurrentUser)scope.ServiceProvider.GetRequiredService<ICurrentUser>();
                using var _ = user.RunAs(SystemActors.Scheduler);

                var query = scope.ServiceProvider.GetRequiredService<AuditQueryService>();
                var result = await query.VerifyChainAsync(ct: ct);

                if (result.Intact)
                    log.LogInformation("Audit chain verified intact");
                else
                    await alerter.AuditFailureAsync(
                        $"Audit chain broken at row {result.FirstBadId}: {result.Reason}",
                        new AuditWriteException(result.Reason ?? "chain mismatch"), ct);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                log.LogError(ex, "Audit chain verification failed to run");
            }
        }
    }
}