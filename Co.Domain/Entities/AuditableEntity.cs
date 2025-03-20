namespace Co.Domain.Entities;

/// <summary>
/// 可审计实体基类，包含创建和修改信息
/// </summary>
/// <typeparam name="TKey">主键类型</typeparam>
public abstract class AuditableEntity<TKey> : Entity<TKey> where TKey : IEquatable<TKey>
{
    /// <summary>
    /// 创建时间
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// 创建人ID
    /// </summary>
    public string CreatedBy { get; set; }

    /// <summary>
    /// 最后修改时间
    /// </summary>
    public DateTime? LastModifiedAt { get; set; }

    /// <summary>
    /// 最后修改人ID
    /// </summary>
    public string LastModifiedBy { get; set; }
}