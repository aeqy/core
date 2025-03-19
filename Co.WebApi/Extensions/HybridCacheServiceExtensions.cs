using Co.Domain.Interfaces;
using Co.Infrastructure.Services;

namespace Co.WebApi.Extensions;


/// <summary>
/// Redis缓存服务扩展类，用于注册HybridCache服务
/// </summary>
public static class HybridCacheServiceExtensions
{
    /// <summary>
    /// 添加混合缓存服务
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection AddHybridCache(this IServiceCollection services, IConfiguration configuration)
    {
        // 配置混合缓存选项
        services.Configure<HybridCacheOptions>(configuration.GetSection("HybridCacheOptions"));

        // 添加内存缓存
        services.AddMemoryCache();

        // 获取Redis连接字符串
        var redisConnectionString = configuration.GetConnectionString("Redis");
        if (string.IsNullOrEmpty(redisConnectionString))
        {
            throw new InvalidOperationException("Redis连接字符串未配置");
        }

        // 添加Redis分布式缓存
        services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = redisConnectionString;
            options.InstanceName = configuration.GetValue<string>("HybridCacheOptions:KeyPrefix") ?? string.Empty;
        });

        // 注册混合缓存服务
        services.AddSingleton<ICacheService, HybridCacheService>();

        return services;
    }
}