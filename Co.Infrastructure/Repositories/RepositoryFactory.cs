using Co.Domain.Interfaces;
using Co.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Co.Infrastructure.Repositories;

/// <summary>
/// 仓储工厂实现
/// </summary>
public class RepositoryFactory : IRepositoryFactory
{
    private readonly CoDbContext _dbContext;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="dbContext">数据库上下文</param>
    public RepositoryFactory(CoDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    /// <summary>
    /// 创建基础仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>仓储实例</returns>
    public IRepository<TEntity> CreateRepository<TEntity>() where TEntity : class
    {
        return new Repository<TEntity>(_dbContext);
    }

    /// <summary>
    /// 创建高级仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>高级仓储实例</returns>
    public IAdvancedRepository<TEntity> CreateAdvancedRepository<TEntity>() where TEntity : class
    {
        return new AdvancedRepository<TEntity>(_dbContext);
    }

    /// <summary>
    /// 创建规约仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>规约仓储实例</returns>
    public ISpecificationRepository<TEntity> CreateSpecificationRepository<TEntity>() where TEntity : class
    {
        return new SpecificationRepository<TEntity>(_dbContext);
    }
}