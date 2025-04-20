using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Co.Identity.Data;

/// <summary>
/// 应用数据库上下文工厂
/// </summary>
public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    /// <summary>
    /// 创建数据库上下文
    /// </summary>
    public ApplicationDbContext CreateDbContext(string[] args)
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json")
            .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development"}.json", true)
            .AddEnvironmentVariables()
            .Build();

        var builder = new DbContextOptionsBuilder<ApplicationDbContext>();
        
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        
        builder.UseNpgsql(connectionString);

        return new ApplicationDbContext(builder.Options);
    }
}

/// <summary>
/// OpenIddict数据库上下文工厂
/// </summary>
public class OpenIddictDbContextFactory : IDesignTimeDbContextFactory<OpenIddictDbContext>
{
    /// <summary>
    /// 创建数据库上下文
    /// </summary>
    public OpenIddictDbContext CreateDbContext(string[] args)
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json")
            .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development"}.json", true)
            .AddEnvironmentVariables()
            .Build();

        var builder = new DbContextOptionsBuilder<OpenIddictDbContext>();
        
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        
        builder.UseNpgsql(connectionString);

        return new OpenIddictDbContext(builder.Options);
    }
} 