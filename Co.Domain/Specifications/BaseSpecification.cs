using System.Linq.Expressions;

namespace Co.Domain.Specifications;

/// <summary>
    /// 规约模式基类实现
    /// </summary>
    /// <typeparam name="T">实体类型</typeparam>
    public abstract class BaseSpecification<T> : ISpecification<T>
    {
        /// <summary>
        /// 查询条件
        /// </summary>
        public Expression<Func<T, bool>> Criteria { get; private set; }

        /// <summary>
        /// 包含的导航属性列表
        /// </summary>
        public List<Expression<Func<T, object>>> Includes { get; } = new List<Expression<Func<T, object>>>();

        /// <summary>
        /// 字符串形式的包含导航属性列表
        /// </summary>
        public List<string> IncludeStrings { get; } = new List<string>();

        /// <summary>
        /// 排序条件
        /// </summary>
        public Expression<Func<T, object>> OrderBy { get; private set; }

        /// <summary>
        /// 降序排序条件
        /// </summary>
        public Expression<Func<T, object>> OrderByDescending { get; private set; }

        /// <summary>
        /// 分组条件
        /// </summary>
        public Expression<Func<T, object>> GroupBy { get; private set; }

        /// <summary>
        /// 分页参数 - 起始位置
        /// </summary>
        public int Skip { get; private set; }

        /// <summary>
        /// 分页参数 - 获取数量
        /// </summary>
        public int Take { get; private set; }

        /// <summary>
        /// 是否启用分页
        /// </summary>
        public bool IsPagingEnabled { get; private set; }

        /// <summary>
        /// 默认构造函数
        /// </summary>
        protected BaseSpecification()
        {
        }

        /// <summary>
        /// 带条件的构造函数
        /// </summary>
        /// <param name="criteria">条件表达式</param>
        protected BaseSpecification(Expression<Func<T, bool>> criteria)
        {
            Criteria = criteria;
        }

        /// <summary>
        /// 添加包含导航属性
        /// </summary>
        /// <param name="includeExpression">包含表达式</param>
        protected void AddInclude(Expression<Func<T, object>> includeExpression)
        {
            Includes.Add(includeExpression);
        }

        /// <summary>
        /// 添加字符串形式的包含导航属性
        /// </summary>
        /// <param name="includeString">导航属性路径</param>
        protected void AddInclude(string includeString)
        {
            IncludeStrings.Add(includeString);
        }

        /// <summary>
        /// 应用分页
        /// </summary>
        /// <param name="skip">跳过记录数</param>
        /// <param name="take">获取记录数</param>
        protected void ApplyPaging(int skip, int take)
        {
            Skip = skip;
            Take = take;
            IsPagingEnabled = true;
        }

        /// <summary>
        /// 应用排序
        /// </summary>
        /// <param name="orderByExpression">排序表达式</param>
        protected void ApplyOrderBy(Expression<Func<T, object>> orderByExpression)
        {
            OrderBy = orderByExpression;
        }

        /// <summary>
        /// 应用降序排序
        /// </summary>
        /// <param name="orderByDescendingExpression">降序排序表达式</param>
        protected void ApplyOrderByDescending(Expression<Func<T, object>> orderByDescendingExpression)
        {
            OrderByDescending = orderByDescendingExpression;
        }

        /// <summary>
        /// 应用分组
        /// </summary>
        /// <param name="groupByExpression">分组表达式</param>
        protected void ApplyGroupBy(Expression<Func<T, object>> groupByExpression)
        {
            GroupBy = groupByExpression;
        }
    }