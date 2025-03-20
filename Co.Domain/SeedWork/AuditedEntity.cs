namespace Co.Domain.SeedWork;

/// <summary>
/// 可审计实体基类
/// 包含创建和修改的审计信息
/// </summary>
public abstract class AuditedEntity : EntityWithEvents, IAudited
{
    /// <summary>
    /// 创建时间
    /// 实体被创建的日期和时间
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// 创建人ID
    /// 创建该实体的用户ID
    /// </summary>
    public Guid CreatedBy { get; set; }

    /// <summary>
    /// 最后修改时间
    /// 实体最后一次被修改的日期和时间，可为空
    /// </summary>
    public DateTime? LastModifiedAt { get; set; }

    /// <summary>
    /// 最后修改人ID
    /// 最后修改该实体的用户ID，可为空
    /// </summary>
    public Guid? LastModifiedBy { get; set; }

    /// <summary>
    /// 默认构造函数
    /// 初始化创建时间为当前UTC时间
    /// </summary>
    protected AuditedEntity()
    {
        CreatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// 带ID参数的构造函数
    /// </summary>
    /// <param name="id">实体ID</param>
    protected AuditedEntity(Guid id) : base(id)
    {
        CreatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// 标记实体为已修改
    /// 更新最后修改时间为当前时间
    /// </summary>
    protected virtual void MarkAsModified()
    {
        LastModifiedAt = DateTime.UtcNow;
    }
}