namespace Co.Domain.Entities;

/// <summary>
/// 令牌黑名单条目
/// </summary>
public class TokenBlacklistEntry(bool isBlacklisted = true)
{
    /// <summary>
    /// 令牌是否在黑名单中
    /// </summary>
    public bool IsBlacklisted { get; set; } = isBlacklisted;

    /// <summary>
    /// 加入黑名单的时间
    /// </summary>
    public DateTime BlacklistedAt { get; set; } = DateTime.UtcNow;
}