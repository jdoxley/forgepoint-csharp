using ForgePoint.Auditing;
using Forgepoint.Data.Util;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Forgepoint.Data;

public class ApplicationDbContext(
    DbContextOptions<ApplicationDbContext> options,
    AuditSaveCoordinator coordinator)
    : AuditableIdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>(options,coordinator)
{
    
    private void OnSave_UpdateTimestamps(object sender, EventArgs e)
    {
        var now = DateTime.UtcNow;
        var entries = ChangeTracker.Entries();
        foreach (var entry in entries)
        {
            if (entry.Entity is DataObject data)
            {
                data.LastEdit = now;
            }
        }
    }
}

