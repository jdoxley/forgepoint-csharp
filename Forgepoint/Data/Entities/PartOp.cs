using Forgepoint.Data.Entities.Components;
using Forgepoint.Data.Util;

namespace Forgepoint.Data.Entities;

public enum Timings
{
    Setup,
    MinPerPart
}

public class PartOp : DataObject<Guid>
{
    public PartOp? Part { get; set; }
    public Guid PartId { get; set; }
    public string Description { get; set; } = "";
    public string OpNumber { get; set; } = "";
    public string Resource { get; set; } = ""; //TODO: Change to actual resource
    public Dictionary<Timings, int> Timings { get; set; } = new();
    public Guid[] ComponentIds { get; set; } = [];
    public ComponentBase[] Components { get; set; } = [];
}