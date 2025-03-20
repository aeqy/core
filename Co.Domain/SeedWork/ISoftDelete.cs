namespace Co.Domain.SeedWork;

/// <summary>
/// 软删除接口
/// 定义支持软删除功能的实体必须实现的属性
/// </summary>
public interface ISoftDelete
{
    /// <summary>
    /// 是否已删除标志
    /// </summary>
    bool IsDeleted { get; set; }

    /// <summary>
    /// 删除时间
    /// </summary>
    DateTime? DeletedAt { get; set; }

    /// <summary>
    /// 删除人ID
    /// </summary>
    Guid? DeletedBy { get; set; }
}