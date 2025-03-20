namespace Co.Domain.SeedWork;

/// <summary>
/// 可审计接口
/// 定义具有审计功能的实体必须实现的属性
/// </summary>
public interface IAudited
{
    /// <summary>
    /// 创建时间
    /// </summary>
    DateTime CreatedAt { get; set; }

    /// <summary>
    /// 创建人ID
    /// </summary>
    Guid CreatedBy { get; set; }

    /// <summary>
    /// 最后修改时间
    /// </summary>
    DateTime? LastModifiedAt { get; set; }

    /// <summary>
    /// 最后修改人ID
    /// </summary>
    Guid? LastModifiedBy { get; set; }
}