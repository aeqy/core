namespace Co.Domain.Entities;

/// <summary>
/// 令牌吊销日志
/// </summary>
public class RefreshToken
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string UserId { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiryTime { get; set; }
    public bool IsRevoked { get; set; }
    public string? RevokedBy { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? ReplacedByToken { get; set; }
}