using Forgepoint.Data.Util;

namespace Forgepoint.Data.Entities;

public class PartRev : DataObject<Guid>
{
    public string Rev { get; set; } = "";
    public Stock[] Stocks { get; set; } = [];
    public Guid[] OpsIds { get; set; } = [];
    public PartOp[] Ops { get; set; } = [];
    public string Notes { get; set; } = "";
    public Part? Part { get; set; }
    public Guid PartId { get; set; }
}

public class Stock
{
    
}