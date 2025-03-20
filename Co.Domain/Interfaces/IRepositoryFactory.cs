namespace Co.Domain.Interfaces;

/// <summary>
/// 仓储工厂接口
/// </summary>
public interface IRepositoryFactory
{
    /// <summary>
    /// 创建基础仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>仓储实例</returns>
    IRepository<TEntity> CreateRepository<TEntity>() where TEntity : class;

    /// <summary>
    /// 创建高级仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>高级仓储实例</returns>
    IAdvancedRepository<TEntity> CreateAdvancedRepository<TEntity>() where TEntity : class;

    /// <summary>
    /// 创建规约仓储
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    /// <returns>规约仓储实例</returns>
    ISpecificationRepository<TEntity> CreateSpecificationRepository<TEntity>() where TEntity : class;
}