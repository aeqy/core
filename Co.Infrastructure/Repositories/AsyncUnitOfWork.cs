using Co.Domain.Interfaces;
using Co.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Co.Infrastructure.Repositories;

/// <summary>
/// 异步工作单元实现类
/// </summary>
public class AsyncUnitOfWork : IAsyncUnitOfWork
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
    public AsyncUnitOfWork(CoDbContext dbContext)
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
    /// <param name="cancellationToken">取消令牌</param>
    /// <returns>受影响的行数</returns>
    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// 开始事务
    /// </summary>
    /// <param name="cancellationToken">取消令牌</param>
    /// <returns>事务对象</returns>
    public async Task<IAsyncUnitOfWorkTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        return new AsyncUnitOfWorkTransaction(await _dbContext.Database.BeginTransactionAsync(cancellationToken));
    }

    /// <summary>
    /// 执行更新SQL语句
    /// </summary>
    /// <param name="sql">SQL语句</param>
    /// <param name="parameters">参数</param>
    /// <returns>影响的行数</returns>
    public async Task<int> ExecuteSqlCommandAsync(string sql, params object[] parameters)
    {
        return await _dbContext.Database.ExecuteSqlRawAsync(sql, parameters);
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
/// 异步工作单元事务实现类
/// </summary>
public sealed class AsyncUnitOfWorkTransaction : IAsyncUnitOfWorkTransaction
{
    private readonly IDbContextTransaction _transaction;
    private bool _disposed;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="transaction">数据库事务</param>
    public AsyncUnitOfWorkTransaction(IDbContextTransaction transaction)
    {
        _transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));
    }

    /// <summary>
    /// 提交事务
    /// </summary>
    /// <param name="cancellationToken">取消令牌</param>
    public async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        await _transaction.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// 回滚事务
    /// </summary>
    /// <param name="cancellationToken">取消令牌</param>
    public async Task RollbackAsync(CancellationToken cancellationToken = default)
    {
        await _transaction.RollbackAsync(cancellationToken);
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
    private void Dispose(bool disposing)
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