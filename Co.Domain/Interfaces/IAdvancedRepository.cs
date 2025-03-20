using System.Linq.Expressions;

namespace Co.Domain.Interfaces;

/// <summary>
/// 高级仓储接口，扩展基本仓储接口，提供更复杂的查询和操作功能
/// </summary>
/// <typeparam name="TEntity">实体类型</typeparam>
public interface IAdvancedRepository<TEntity> : IRepository<TEntity> where TEntity : class
{
    /// <summary>
    /// 获取分页数据
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <param name="orderBy">排序方式</param>
    /// <param name="includeProperties">包含的导航属性</param>
    /// <param name="pageIndex">页码，从0开始</param>
    /// <param name="pageSize">每页记录数</param>
    /// <returns>分页后的实体集合</returns>
    Task<(IEnumerable<TEntity> Items, int TotalCount)> GetPagedAsync(
        Expression<Func<TEntity, bool>> filter = null,
        Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>> orderBy = null,
        string includeProperties = "",
        int pageIndex = 0,
        int pageSize = 10);

    /// <summary>
    /// 获取单个实体，包括指定的导航属性
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <param name="includeProperties">包含的导航属性，用逗号分隔</param>
    /// <returns>实体对象</returns>
    Task<TEntity> GetFirstOrDefaultAsync(
        Expression<Func<TEntity, bool>> filter = null,
        string includeProperties = "");

    /// <summary>
    /// 获取满足条件的实体数量
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <returns>满足条件的实体数量</returns>
    Task<int> CountAsync(Expression<Func<TEntity, bool>> filter = null);

    /// <summary>
    /// 使用原始SQL查询获取实体
    /// </summary>
    /// <param name="sql">SQL查询语句</param>
    /// <param name="parameters">SQL参数</param>
    /// <returns>查询结果</returns>
    Task<IEnumerable<TEntity>> QueryWithRawSqlAsync(string sql, params object[] parameters);

    /// <summary>
    /// 批量更新
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <param name="updateExpression">更新表达式</param>
    /// <returns>更新的记录数</returns>
    Task<int> BatchUpdateAsync(Expression<Func<TEntity, bool>> filter,
        Expression<Func<TEntity, TEntity>> updateExpression);

    /// <summary>
    /// 批量删除
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <returns>删除的记录数</returns>
    Task<int> BatchDeleteAsync(Expression<Func<TEntity, bool>> filter);
}