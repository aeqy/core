namespace Co.Domain.Entities.Materials;

/// <summary>
/// 物料状态枚举
/// </summary>
public enum MaterialStatus
{
    /// <summary>
    /// 活跃状态 - 可用于所有业务操作
    /// </summary>
    Active = 0,

    /// <summary>
    /// 非活跃状态 - 暂时不可用于新业务操作
    /// </summary>
    Inactive = 1,

    /// <summary>
    /// 废弃状态 - 永久不可用于新业务操作
    /// </summary>
    Obsolete = 2
}