using Ganss.Xss;

namespace Forgepoint.Data.Entities.Components;

public class WrittenDescription : ComponentBase
{
    public string Content
    {
        get;
        set
        {
            var san = new HtmlSanitizer();
            field = san.Sanitize(value);
        }
    } = "";

    public WrittenDescription()
    {
        Name = "Written Description";
        Order = 1;
    }
}