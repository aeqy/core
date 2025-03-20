namespace Co.Domain.SeedWork;


/// <summary>
/// 完整审计实体基类
/// 包含创建、修改和软删除的审计信息
/// </summary>
public abstract class FullAuditedEntity : AuditedEntity, IFullAudited
{
    /// <summary>
    /// 是否已删除标志
    /// 用于软删除功能，标记实体是否已被删除
    /// </summary>
    public bool IsDeleted { get; set; }

    /// <summary>
    /// 删除时间
    /// 实体被删除的日期和时间，可为空
    /// </summary>
    public DateTime? DeletedAt { get; set; }

    /// <summary>
    /// 删除人ID
    /// 删除该实体的用户ID，可为空
    /// </summary>
    public Guid? DeletedBy { get; set; }

    /// <summary>
    /// 默认构造函数
    /// </summary>
    protected FullAuditedEntity()
    {
        IsDeleted = false;
    }

    /// <summary>
    /// 带ID参数的构造函数
    /// </summary>
    /// <param name="id">实体ID</param>
    protected FullAuditedEntity(Guid id) : base(id)
    {
        IsDeleted = false;
    }

    /// <summary>
    /// 标记实体为已删除
    /// 设置删除标志和删除时间
    /// </summary>
    protected virtual void MarkAsDeleted()
    {
        IsDeleted = true;
        DeletedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// 恢复已删除的实体
    /// 清除删除标志和删除时间
    /// </summary>
    protected virtual void Restore()
    {
        IsDeleted = false;
        DeletedAt = null;
        DeletedBy = null;
        MarkAsModified();
    }
}