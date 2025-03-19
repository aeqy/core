using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Co.Infrastructure.Data;

/// <summary>
/// 数据库上下文服务集合扩展
/// </summary>
public static class DbContextServiceCollectionExtensions
{
    /// <summary>
    /// 添加数据库服务
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection AddDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        // 配置 DbContext
        services.AddDbContext<CoDbContext>(options =>
        {
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"),
                npgsql =>
                {
                    // 配置迁移程序集
                    npgsql.MigrationsAssembly(typeof(CoDbContext).Assembly.GetName().Name);
                    // 启用重试机制
                    npgsql.EnableRetryOnFailure();
                });
            
            // 开发环境下启用详细错误信息和敏感数据记录
            if (configuration.GetValue<bool>("EnableDetailedDbLogging", false))
            {
                options.EnableDetailedErrors();
                options.EnableSensitiveDataLogging();
            }
        });

        return services;
    }
}