using System.Web;
using Npgsql;

namespace ForgePoint.Auditing;

/// <summary>
/// Reads and validates a Postgres connection string at startup rather than on
/// the first circuit. A malformed string should stop the application booting,
/// not surface as an ArgumentException in the middle of someone's shift.
/// </summary>
public static class PostgresConnectionString
{
    public static NpgsqlDataSource CreateDataSource(
        IConfiguration config, string connectionName)
    {
        var raw = config.GetConnectionString(connectionName);

        if (string.IsNullOrWhiteSpace(raw))
            throw new InvalidOperationException(
                $"Connection string 'ConnectionStrings:{connectionName}' is missing or empty. " +
                $"ForgePoint auditing needs two: 'ForgePoint' (the {"forgepoint_app"} role, " +
                $"INSERT-only on audit) and 'ForgePointAuditor' (the forgepoint_auditor role, " +
                $"SELECT-only on audit).");

        var normalised = Normalise(raw.Trim(), connectionName);

        try
        {
            return NpgsqlDataSource.Create(normalised);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Connection string 'ConnectionStrings:{connectionName}' is not a valid Npgsql " +
                $"connection string. Npgsql wants keyword form, e.g. " +
                $"\"Host=localhost;Port=5432;Database=forgepoint;Username=forgepoint_app;Password=...\". " +
                $"First 12 characters received: \"{Preview(normalised)}\". " +
                $"(Value redacted; check appsettings or user-secrets.)", ex);
        }
    }

    /// <summary>
    /// Accepts the URI form that psql, Docker, and most hosted Postgres
    /// services hand out, and converts it to the keyword form Npgsql requires.
    /// Keyword strings pass through untouched.
    /// </summary>
    public static string Normalise(string value, string connectionName)
    {
        if (!value.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase) &&
            !value.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase))
        {
            return value;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            throw new InvalidOperationException(
                $"Connection string 'ConnectionStrings:{connectionName}' looks like a Postgres " +
                $"URI but could not be parsed. Convert it to keyword form manually.");

        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = uri.Host,
            Port = uri.IsDefaultPort || uri.Port <= 0 ? 5432 : uri.Port,
            Database = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'))
        };

        var userInfo = uri.UserInfo.Split(':', 2);
        if (userInfo.Length > 0 && userInfo[0].Length > 0)
            builder.Username = Uri.UnescapeDataString(userInfo[0]);
        if (userInfo.Length > 1)
            builder.Password = Uri.UnescapeDataString(userInfo[1]);

        // Carry over the query parameters people actually use.
        var q = HttpUtility.ParseQueryString(uri.Query);
        foreach (string? key in q)
        {
            if (key is null) continue;
            var v = q[key];
            if (string.IsNullOrEmpty(v)) continue;

            switch (key.ToLowerInvariant())
            {
                case "sslmode":
                    if (Enum.TryParse<SslMode>(v, ignoreCase: true, out var mode))
                        builder.SslMode = mode;
                    break;
                case "application_name":
                    builder.ApplicationName = v;
                    break;
                case "search_path":
                    builder.SearchPath = v;
                    break;
                // Anything else, hand it straight to the builder and let it
                // complain if the key is unknown.
                default:
                    builder[key] = v;
                    break;
            }
        }

        return builder.ConnectionString;
    }

    private static string Preview(string value) =>
        value.Length <= 12 ? value : value[..12] + "...";
}