namespace Co.Domain.SeedWork;

/// <summary>
/// 可审计聚合根基类
/// 结合了聚合根和审计功能
/// </summary>
public abstract class AuditedAggregateRoot : AuditedEntity, IAggregateRoot
{
    /// <summary>
    /// 默认构造函数
    /// </summary>
    protected AuditedAggregateRoot()
    {
    }

    /// <summary>
    /// 带ID参数的构造函数
    /// </summary>
    /// <param name="id">聚合根ID</param>
    protected AuditedAggregateRoot(Guid id) : base(id)
    {
    }
}