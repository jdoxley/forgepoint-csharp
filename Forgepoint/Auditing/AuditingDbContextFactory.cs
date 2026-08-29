using Microsoft.EntityFrameworkCore;

namespace ForgePoint.Auditing;

/// <summary>
/// Blazor Server needs IDbContextFactory (a circuit-lifetime DbContext is not
/// safe), but the stock AddDbContextFactory builds contexts from a singleton
/// options object and cannot see circuit-scoped services like ICurrentUser.
///
/// This factory is registered scoped, so every context it produces is bound to
/// the identity of the circuit that asked for it. Options stay singleton.
///
/// Your context needs a constructor of the shape:
///   public AppDbContext(DbContextOptions&lt;AppDbContext&gt; options,
///                       AuditSaveCoordinator coordinator)
///       : base(options, coordinator) { }
///
/// This works for either base class - AuditableDbContext or
/// AuditableIdentityDbContext - since both satisfy IAuditableContext.
/// </summary>
public sealed class AuditingDbContextFactory<TContext>(
    DbContextOptions<TContext> options,
    AuditSaveCoordinator coordinator) : IDbContextFactory<TContext>
    where TContext : DbContext, IAuditableContext
{
    public TContext CreateDbContext() =>
        (TContext)Activator.CreateInstance(typeof(TContext), options, coordinator)!;
}