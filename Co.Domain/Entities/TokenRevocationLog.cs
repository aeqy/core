namespace Co.Domain.Entities;

/// <summary>
/// 令牌吊销日志实体
/// 用于记录访问令牌和刷新令牌的吊销历史
/// </summary>
public class TokenRevocationLog
{
    /// <summary>
    /// 日志唯一标识符
    /// </summary>
    /// <remarks>
    /// 使用 GUID 作为主键，确保在分布式系统中的唯一性
    /// </remarks>
    public Guid Id { get; set; }

    /// <summary>
    /// 令牌所属用户的唯一标识符
    /// </summary>
    /// <remarks>
    /// 关联到 IdentityUser 表的 Id 字段
    /// 用于追踪令牌是属于哪个用户的
    /// </remarks>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// 被吊销的令牌类型
    /// </summary>
    /// <remarks>
    /// 可能的值包括：
    /// - access_token：访问令牌
    /// - refresh_token：刷新令牌
    /// - id_token：身份令牌
    /// </remarks>
    public string TokenType { get; set; } = string.Empty;

    /// <summary>
    /// 令牌吊销的时间戳
    /// </summary>
    /// <remarks>
    /// 使用 UTC 时间，便于跨时区比较和处理
    /// </remarks>
    public DateTime RevokedAt { get; set; }

    /// <summary>
    /// 令牌被吊销的原因
    /// </summary>
    /// <remarks>
    /// 可能的原因包括：
    /// - 用户主动注销
    /// - 管理员强制吊销
    /// - 安全策略触发
    /// - 密码更改
    /// - 检测到可疑活动
    /// 等等
    /// </remarks>
    public string? Reason { get; set; }

    /// <summary>
    /// 执行吊销操作的主体
    /// </summary>
    /// <remarks>
    /// 可能的值包括：
    /// - 用户ID（用户主动注销）
    /// - 管理员ID（管理员操作）
    /// - System（系统自动操作）
    /// - SecurityPolicy（安全策略触发）
    /// </remarks>
    public string? RevokedBy { get; set; }

    /// <summary>
    /// 令牌的哈希值
    /// </summary>
    /// <remarks>
    /// 出于安全考虑，不存储原始令牌
    /// 仅存储令牌的哈希值用于审计和追踪
    /// </remarks>
    public string? TokenHash { get; set; }

    /// <summary>
    /// 吊销操作的IP地址
    /// </summary>
    /// <remarks>
    /// 记录执行吊销操作时的客户端IP地址
    /// 用于安全审计和追踪
    /// </remarks>
    public string? IpAddress { get; set; }

    /// <summary>
    /// 吊销操作的用户代理信息
    /// </summary>
    /// <remarks>
    /// 记录执行吊销操作时的浏览器/客户端信息
    /// 用于安全审计和追踪
    /// </remarks>
    public string? UserAgent { get; set; }

    /// <summary>
    /// 关联的会话ID
    /// </summary>
    /// <remarks>
    /// 如果吊销是由于会话结束导致的
    /// 则记录相关的会话ID
    /// </remarks>
    public string? SessionId { get; set; }

    /// <summary>
    /// 吊销操作的额外元数据
    /// </summary>
    /// <remarks>
    /// 存储为JSON格式的额外信息
    /// 用于记录特定场景下的补充信息
    /// </remarks>
    public string? Metadata { get; set; }

    /// <summary>
    /// 创建令牌吊销日志
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <param name="tokenType">令牌类型</param>
    /// <param name="reason">吊销原因</param>
    /// <returns>新的令牌吊销日志实例</returns>
    public static TokenRevocationLog Create(string userId, string tokenType, string reason)
    {
        return new TokenRevocationLog
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenType = tokenType,
            RevokedAt = DateTime.UtcNow,
            Reason = reason,
            RevokedBy = "System"
        };
    }

    /// <summary>
    /// 添加客户端信息
    /// </summary>
    /// <param name="ipAddress">IP地址</param>
    /// <param name="userAgent">用户代理</param>
    public void AddClientInfo(string? ipAddress, string? userAgent)
    {
        IpAddress = ipAddress;
        UserAgent = userAgent;
    }

    /// <summary>
    /// 设置吊销者信息
    /// </summary>
    /// <param name="revokedBy">执行吊销的主体</param>
    public void SetRevokedBy(string revokedBy)
    {
        RevokedBy = revokedBy;
    }

    /// <summary>
    /// 添加令牌哈希
    /// </summary>
    /// <param name="token">原始令牌</param>
    public void AddTokenHash(string token)
    {
        // 使用SHA256对令牌进行哈希处理
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(token));
        TokenHash = Convert.ToBase64String(hashBytes);
    }
}