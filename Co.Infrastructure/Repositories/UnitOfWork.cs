using Co.Domain.Interfaces;
using Co.Infrastructure.Data;
using Microsoft.EntityFrameworkCore.Storage;

namespace Co.Infrastructure.Repositories;

/// <summary>
/// 工作单元实现类，基于EF Core
/// </summary>
public class UnitOfWork : IUnitOfWork
{
    private readonly CoDbContext _dbContext;
    private readonly Dictionary<Type, object> _repositories;
    private readonly Dictionary<Type, object> _advancedRepositories;
    private readonly Dictionary<Type, object> _specificationRepositories;
    private bool _disposed;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="dbContext">数据库上下文</param>
    public UnitOfWork(CoDbContext dbContext)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _repositories = new Dictionary<Type, object>();
        _advancedRepositories = new Dictionary<Type, object>();
        _specificationRepositories = new Dictionary<Type, object>();
    }

    /// <summary>
    /// 获取基本仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>仓储实例</returns>
    public IRepository<TEntity> GetRepository<TEntity>() where TEntity : class
    {
        var type = typeof(TEntity);

        if (!_repositories.ContainsKey(type))
        {
            _repositories[type] = new Repository<TEntity>(_dbContext);
        }

        return (IRepository<TEntity>)_repositories[type];
    }

    /// <summary>
    /// 获取高级仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>高级仓储实例</returns>
    public IAdvancedRepository<TEntity> GetAdvancedRepository<TEntity>() where TEntity : class
    {
        var type = typeof(TEntity);

        if (!_advancedRepositories.ContainsKey(type))
        {
            _advancedRepositories[type] = new AdvancedRepository<TEntity>(_dbContext);
        }

        return (IAdvancedRepository<TEntity>)_advancedRepositories[type];
    }

    /// <summary>
    /// 获取规约仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>规约仓储实例</returns>
    public ISpecificationRepository<TEntity> GetSpecificationRepository<TEntity>() where TEntity : class
    {
        var type = typeof(TEntity);

        if (!_specificationRepositories.ContainsKey(type))
        {
            _specificationRepositories[type] = new SpecificationRepository<TEntity>(_dbContext);
        }

        return (ISpecificationRepository<TEntity>)_specificationRepositories[type];
    }

    /// <summary>
    /// 保存更改
    /// </summary>
    /// <returns>受影响的行数</returns>
    public async Task<int> SaveChangesAsync()
    {
        return await _dbContext.SaveChangesAsync();
    }

    /// <summary>
    /// 开始事务
    /// </summary>
    /// <returns>事务对象</returns>
    public async Task<IUnitOfWorkTransaction> BeginTransactionAsync()
    {
        return new UnitOfWorkTransaction(await _dbContext.Database.BeginTransactionAsync());
    }

    /// <summary>
    /// 释放资源
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// 释放资源
    /// </summary>
    /// <param name="disposing">是否释放托管资源</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _dbContext.Dispose();
            }

            _disposed = true;
        }
    }
}

/// <summary>
/// 工作单元事务实现类
/// </summary>
public class UnitOfWorkTransaction : IUnitOfWorkTransaction
{
    private readonly IDbContextTransaction _transaction;
    private bool _disposed;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="transaction">数据库事务</param>
    public UnitOfWorkTransaction(IDbContextTransaction transaction)
    {
        _transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));
    }

    /// <summary>
    /// 提交事务
    /// </summary>
    public async Task CommitAsync()
    {
        await _transaction.CommitAsync();
    }

    /// <summary>
    /// 回滚事务
    /// </summary>
    public async Task RollbackAsync()
    {
        await _transaction.RollbackAsync();
    }

    /// <summary>
    /// 释放资源
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// 释放资源
    /// </summary>
    /// <param name="disposing">是否释放托管资源</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _transaction.Dispose();
            }

            _disposed = true;
        }
    }
}