namespace Co.Domain.SeedWork;

/// <summary>
/// 完整审计聚合根基类
/// 结合了聚合根、审计和软删除功能
/// </summary>
public abstract class FullAuditedAggregateRoot : FullAuditedEntity, IAggregateRoot
{
    /// <summary>
    /// 默认构造函数
    /// </summary>
    protected FullAuditedAggregateRoot()
    {
    }

    /// <summary>
    /// 带ID参数的构造函数
    /// </summary>
    /// <param name="id">聚合根ID</param>
    protected FullAuditedAggregateRoot(Guid id) : base(id)
    {
    }
}