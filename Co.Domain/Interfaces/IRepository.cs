using System.Linq.Expressions;

namespace Co.Domain.Interfaces;

/// <summary>
/// 通用仓储接口，定义对实体的基本操作
/// </summary>
/// <typeparam name="TEntity">实体类型</typeparam>
public interface IRepository<TEntity> where TEntity : class
{
    /// <summary>
    /// 获取所有实体
    /// </summary>
    /// <returns>实体集合</returns>
    Task<IEnumerable<TEntity>> GetAllAsync();

    /// <summary>
    /// 根据条件查询实体
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <returns>满足条件的实体集合</returns>
    Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> filter);

    /// <summary>
    /// 根据主键获取实体
    /// </summary>
    /// <param name="id">主键值</param>
    /// <returns>实体对象</returns>
    Task<TEntity> GetByIdAsync(object id);

    /// <summary>
    /// 添加实体
    /// </summary>
    /// <param name="entity">实体对象</param>
    Task AddAsync(TEntity entity);

    /// <summary>
    /// 批量添加实体
    /// </summary>
    /// <param name="entities">实体集合</param>
    Task AddRangeAsync(IEnumerable<TEntity> entities);

    /// <summary>
    /// 更新实体
    /// </summary>
    /// <param name="entity">实体对象</param>
    void Update(TEntity entity);

    /// <summary>
    /// 批量更新实体
    /// </summary>
    /// <param name="entities">实体集合</param>
    void UpdateRange(IEnumerable<TEntity> entities);

    /// <summary>
    /// 删除实体
    /// </summary>
    /// <param name="entity">实体对象</param>
    void Delete(TEntity entity);

    /// <summary>
    /// 根据主键删除实体
    /// </summary>
    /// <param name="id">主键值</param>
    Task DeleteByIdAsync(object id);

    /// <summary>
    /// 批量删除实体
    /// </summary>
    /// <param name="entities">实体集合</param>
    void DeleteRange(IEnumerable<TEntity> entities);

    /// <summary>
    /// 获取查询对象
    /// </summary>
    /// <returns>查询对象</returns>
    IQueryable<TEntity> Query();

    /// <summary>
    /// 检查实体是否存在
    /// </summary>
    /// <param name="filter">检查条件</param>
    /// <returns>存在返回true，否则返回false</returns>
    Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> filter);
}