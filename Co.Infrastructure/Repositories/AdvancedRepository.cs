using System.Linq.Expressions;
using Co.Domain.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Co.Infrastructure.Repositories;

/// <summary>
/// 高级仓储实现类
/// </summary>
/// <typeparam name="TEntity">实体类型</typeparam>
public class AdvancedRepository<TEntity> : Repository<TEntity>, IAdvancedRepository<TEntity> where TEntity : class
{
    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="context">数据库上下文</param>
    public AdvancedRepository(DbContext context) : base(context)
    {
    }

    /// <summary>
    /// 获取分页数据
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <param name="orderBy">排序方式</param>
    /// <param name="includeProperties">包含的导航属性</param>
    /// <param name="pageIndex">页码，从0开始</param>
    /// <param name="pageSize">每页记录数</param>
    /// <returns>分页后的实体集合</returns>
    public async Task<(IEnumerable<TEntity> Items, int TotalCount)> GetPagedAsync(
        Expression<Func<TEntity, bool>> filter = null,
        Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>> orderBy = null,
        string includeProperties = "",
        int pageIndex = 0,
        int pageSize = 10)
    {
        IQueryable<TEntity> query = DbSet;

        // 应用过滤条件
        if (filter != null)
        {
            query = query.Where(filter);
        }

        // 计算总记录数
        var totalCount = await query.CountAsync();

        // 包含导航属性
        foreach (var includeProperty in includeProperties.Split
                     (new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            query = query.Include(includeProperty);
        }

        // 应用排序
        if (orderBy != null)
        {
            query = orderBy(query);
        }

        // 分页
        var items = await query.Skip(pageIndex * pageSize).Take(pageSize).ToListAsync();

        return (items, totalCount);
    }

    /// <summary>
    /// 获取单个实体，包括指定的导航属性
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <param name="includeProperties">包含的导航属性，用逗号分隔</param>
    /// <returns>实体对象</returns>
    public async Task<TEntity> GetFirstOrDefaultAsync(
        Expression<Func<TEntity, bool>> filter = null,
        string includeProperties = "")
    {
        IQueryable<TEntity> query = DbSet;

        // 应用过滤条件
        if (filter != null)
        {
            query = query.Where(filter);
        }

        // 包含导航属性
        foreach (var includeProperty in includeProperties.Split
                     (new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            query = query.Include(includeProperty);
        }

        return await query.FirstOrDefaultAsync();
    }

    /// <summary>
    /// 获取满足条件的实体数量
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <returns>满足条件的实体数量</returns>
    public async Task<int> CountAsync(Expression<Func<TEntity, bool>> filter = null)
    {
        IQueryable<TEntity> query = DbSet;

        if (filter != null)
        {
            query = query.Where(filter);
        }

        return await query.CountAsync();
    }

    /// <summary>
    /// 使用原始SQL查询获取实体
    /// </summary>
    /// <param name="sql">SQL查询语句</param>
    /// <param name="parameters">SQL参数</param>
    /// <returns>查询结果</returns>
    public async Task<IEnumerable<TEntity>> QueryWithRawSqlAsync(string sql, params object[] parameters)
    {
        return await DbSet.FromSqlRaw(sql, parameters).ToListAsync();
    }

    /// <summary>
    /// 批量更新
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <param name="updateExpression">更新表达式</param>
    /// <returns>更新的记录数</returns>
    public async Task<int> BatchUpdateAsync(Expression<Func<TEntity, bool>> filter,
        Expression<Func<TEntity, TEntity>> updateExpression)
    {
        // 注意：此方法需要EF Core扩展或第三方库支持，如EF Core Plus或Z.EntityFramework.Plus
        // 以下为简化实现，实际项目中应使用更高效的批量更新方法
        var entities = await DbSet.Where(filter).ToListAsync();
        foreach (var entity in entities)
        {
            Update(entity);
        }

        return entities.Count;
    }

    /// <summary>
    /// 批量删除
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <returns>删除的记录数</returns>
    public async Task<int> BatchDeleteAsync(Expression<Func<TEntity, bool>> filter)
    {
        // 注意：此方法需要EF Core扩展或第三方库支持，如EF Core Plus或Z.EntityFramework.Plus
        // 以下为简化实现，实际项目中应使用更高效的批量删除方法
        var entities = await DbSet.Where(filter).ToListAsync();
        DbSet.RemoveRange(entities);
        return entities.Count;
    }
}