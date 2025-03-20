using Co.Domain.Interfaces;
using Co.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;

namespace Co.WebApi.Extensions;

/// <summary>
/// 仓储和工作单元服务注册扩展方法
/// </summary>
public static class RepositoryServiceExtensions
{
    /// <summary>
    /// 注册仓储和工作单元
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection AddRepositories(this IServiceCollection services)
    {
        // 注册仓储工厂
        services.AddScoped<IRepositoryFactory, RepositoryFactory>();

        // 注册工作单元工厂
        services.AddScoped<IUnitOfWorkFactory, UnitOfWorkFactory>();

        // 注册基础仓库
        services.AddScoped(typeof(IRepository<>), typeof(Repository<>));

        // 注册高级仓库（如果需要）
        services.AddScoped(typeof(IAdvancedRepository<>), typeof(AdvancedRepository<>));

        // 注册规约仓库（如果需要）
        services.AddScoped(typeof(ISpecificationRepository<>), typeof(SpecificationRepository<>));

        return services;
    }
}