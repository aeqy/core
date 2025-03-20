namespace Co.Domain.Entities;

/// <summary>
/// 软删除实体基类，支持逻辑删除
/// </summary>
/// <typeparam name="TKey">主键类型</typeparam>
public abstract class SoftDeleteEntity<TKey> : AuditableEntity<TKey> where TKey : IEquatable<TKey>
{
    /// <summary>
    /// 是否已删除
    /// </summary>
    public bool IsDeleted { get; set; }

    /// <summary>
    /// 删除时间
    /// </summary>
    public DateTime? DeletedAt { get; set; }

    /// <summary>
    /// 删除人ID
    /// </summary>
    public string DeletedBy { get; set; }
}