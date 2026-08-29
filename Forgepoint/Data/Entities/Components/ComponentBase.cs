using Forgepoint.Data.Util;

namespace Forgepoint.Data.Entities.Components;

public class ComponentBase : DataObject<Guid>
{
    public string Name { get; set; } = "";
    public int Order { get; set; } = 0;
}