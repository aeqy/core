using System.Linq.Expressions;

namespace Co.Domain.Specifications;

/// <summary>
/// 规约接口，用于封装查询条件
/// </summary>
/// <typeparam name="T">实体类型</typeparam>
public interface ISpecification<T>
{
    /// <summary>
    /// 获取条件表达式
    /// </summary>
    Expression<Func<T, bool>> Criteria { get; }

    /// <summary>
    /// 获取包含的导航属性
    /// </summary>
    List<Expression<Func<T, object>>> Includes { get; }

    /// <summary>
    /// 获取字符串形式的包含导航属性
    /// </summary>
    List<string> IncludeStrings { get; }

    /// <summary>
    /// 获取排序条件
    /// </summary>
    Expression<Func<T, object>> OrderBy { get; }

    /// <summary>
    /// 获取降序排序条件
    /// </summary>
    Expression<Func<T, object>> OrderByDescending { get; }

    /// <summary>
    /// 获取分组条件
    /// </summary>
    Expression<Func<T, object>> GroupBy { get; }

    /// <summary>
    /// 获取分页参数 - 起始位置
    /// </summary>
    int Skip { get; }

    /// <summary>
    /// 获取分页参数 - 获取数量
    /// </summary>
    int Take { get; }

    /// <summary>
    /// 是否启用分页
    /// </summary>
    bool IsPagingEnabled { get; }
}