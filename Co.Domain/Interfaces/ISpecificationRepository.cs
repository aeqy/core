using Co.Domain.Specifications;

namespace Co.Domain.Interfaces;

/// <summary>
/// 支持规约模式的仓储接口
/// </summary>
/// <typeparam name="TEntity">实体类型</typeparam>
public interface ISpecificationRepository<TEntity> : IRepository<TEntity> where TEntity : class
{
    /// <summary>
    /// 使用规约获取单个实体
    /// </summary>
    /// <param name="specification">规约对象</param>
    /// <returns>实体对象</returns>
    Task<TEntity> GetSingleBySpecAsync(ISpecification<TEntity> specification);

    /// <summary>
    /// 使用规约获取实体列表
    /// </summary>
    /// <param name="specification">规约对象</param>
    /// <returns>实体列表</returns>
    Task<List<TEntity>> GetListBySpecAsync(ISpecification<TEntity> specification);

    /// <summary>
    /// 使用规约获取实体数量
    /// </summary>
    /// <param name="specification">规约对象</param>
    /// <returns>实体数量</returns>
    Task<int> CountBySpecAsync(ISpecification<TEntity> specification);

    /// <summary>
    /// 使用规约检查是否存在满足条件的实体
    /// </summary>
    /// <param name="specification">规约对象</param>
    /// <returns>是否存在</returns>
    Task<bool> ExistsBySpecAsync(ISpecification<TEntity> specification);
}