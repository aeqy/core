namespace Co.Domain.Interfaces;

/// <summary>
/// 异步工作单元接口
/// </summary>
public interface IAsyncUnitOfWork : IDisposable
{
    /// <summary>
    /// 获取指定实体类型的仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>对应的仓储实例</returns>
    IRepository<TEntity> GetRepository<TEntity>() where TEntity : class;

    /// <summary>
    /// 获取指定实体类型的高级仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>对应的高级仓储实例</returns>
    IAdvancedRepository<TEntity> GetAdvancedRepository<TEntity>() where TEntity : class;

    /// <summary>
    /// 获取指定实体类型的规约仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>对应的规约仓储实例</returns>
    ISpecificationRepository<TEntity> GetSpecificationRepository<TEntity>() where TEntity : class;

    /// <summary>
    /// 保存所有更改
    /// </summary>
    /// <param name="cancellationToken">取消令牌</param>
    /// <returns>受影响的行数</returns>
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 开始一个新的事务
    /// </summary>
    /// <param name="cancellationToken">取消令牌</param>
    /// <returns>事务对象</returns>
    Task<IAsyncUnitOfWorkTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 执行更新SQL语句
    /// </summary>
    /// <param name="sql">SQL语句</param>
    /// <param name="parameters">参数</param>
    /// <returns>影响的行数</returns>
    Task<int> ExecuteSqlCommandAsync(string sql, params object[] parameters);
}

/// <summary>
/// 异步工作单元事务接口
/// </summary>
public interface IAsyncUnitOfWorkTransaction : IDisposable
{
    /// <summary>
    /// 提交事务
    /// </summary>
    /// <param name="cancellationToken">取消令牌</param>
    Task CommitAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// 回滚事务
    /// </summary>
    /// <param name="cancellationToken">取消令牌</param>
    Task RollbackAsync(CancellationToken cancellationToken = default);
}