namespace Co.Domain.SeedWork;

/// <summary>
/// 聚合根基类
/// 聚合根是一个领域概念，代表一个事务一致性的边界
/// 所有对聚合的修改必须通过聚合根进行
/// </summary>
public abstract class AggregateRoot : EntityWithEvents, IAggregateRoot
{
    /// <summary>
    /// 默认构造函数
    /// </summary>
    protected AggregateRoot()
    {
    }

    /// <summary>
    /// 带ID参数的构造函数
    /// </summary>
    /// <param name="id">聚合根ID</param>
    protected AggregateRoot(Guid id) : base(id)
    {
    }
}