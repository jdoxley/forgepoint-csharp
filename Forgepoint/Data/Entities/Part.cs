using Forgepoint.Data.Util;

namespace Forgepoint.Data.Entities;

public class Part : DataObject<Guid>
{
    public string PartNumber { get; set; } = "";
    public string Description { get; set; } = "";
    public string Name { get; set; } = "";
    public Guid ClientId { get; set; }
    public Guid ActiveRevId { get; set; }
    public PartRev? ActiveRev { get; set; }
    public PartRev[] Revs { get; set; } = [];
    public Guid[] RevIds { get; set; } = [];
    public bool Itar { get; set; } = false;
}