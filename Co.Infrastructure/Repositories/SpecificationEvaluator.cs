using Co.Domain.Specifications;
using Microsoft.EntityFrameworkCore;

namespace Co.Infrastructure.Repositories;

/// <summary>
/// 规约评估器，将规约转换为查询
/// </summary>
/// <typeparam name="TEntity">实体类型</typeparam>
public class SpecificationEvaluator<TEntity> where TEntity : class
{
    /// <summary>
    /// 将规约应用到查询
    /// </summary>
    /// <param name="inputQuery">输入查询</param>
    /// <param name="specification">规约对象</param>
    /// <returns>应用规约后的查询</returns>
    public static IQueryable<TEntity> GetQuery(IQueryable<TEntity> inputQuery, ISpecification<TEntity> specification)
    {
        var query = inputQuery;

        // 应用条件过滤
        if (specification.Criteria != null)
        {
            query = query.Where(specification.Criteria);
        }

        // 应用排序
        if (specification.OrderBy != null)
        {
            query = query.OrderBy(specification.OrderBy);
        }
        else if (specification.OrderByDescending != null)
        {
            query = query.OrderByDescending(specification.OrderByDescending);
        }

        // 应用分组
        if (specification.GroupBy != null)
        {
            query = query.GroupBy(specification.GroupBy).SelectMany(x => x);
        }

        // 应用包含
        query = specification.Includes.Aggregate(query,
            (current, include) => current.Include(include));

        // 应用字符串包含
        query = specification.IncludeStrings.Aggregate(query,
            (current, include) => current.Include(include));

        // 应用分页
        if (specification.IsPagingEnabled)
        {
            query = query.Skip(specification.Skip)
                .Take(specification.Take);
        }

        return query;
    }
}