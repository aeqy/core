namespace Co.Domain.Entities;

/// <summary>
/// 用户注销日志
/// </summary>
public class UserLogoutLog
{
    /// <summary>
    /// 日志ID
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// 用户ID
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// 注销时间
    /// </summary>
    public DateTime LogoutTime { get; set; }

    /// <summary>
    /// 注销类型（如：主动注销、会话过期、管理员强制注销等）
    /// </summary>
    public string LogoutType { get; set; } = string.Empty;

    /// <summary>
    /// 发起注销的主体（用户自己、系统、管理员等）
    /// </summary>
    public string InitiatedBy { get; set; } = string.Empty;

    /// <summary>
    /// 客户端IP
    /// </summary>
    public string? ClientIp { get; set; }

    /// <summary>
    /// 用户代理（浏览器信息）
    /// </summary>
    public string? UserAgent { get; set; }
}