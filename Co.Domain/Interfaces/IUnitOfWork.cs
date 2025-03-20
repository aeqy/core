namespace Co.Domain.Interfaces;

/// <summary>
/// 工作单元接口，用于管理事务和仓储
/// </summary>
public interface IUnitOfWork : IDisposable
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
    /// 保存所有更改
    /// </summary>
    /// <returns>受影响的行数</returns>
    Task<int> SaveChangesAsync();

    /// <summary>
    /// 开始一个新的事务
    /// </summary>
    /// <returns>事务对象</returns>
    Task<IUnitOfWorkTransaction> BeginTransactionAsync();
}

/// <summary>
/// 工作单元事务接口
/// </summary>
public interface IUnitOfWorkTransaction : IDisposable
{
    /// <summary>
    /// 提交事务
    /// </summary>
    Task CommitAsync();

    /// <summary>
    /// 回滚事务
    /// </summary>
    Task RollbackAsync();
}