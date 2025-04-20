namespace Co.Identity.Models;

public class RevokedToken
{
    public int Id { get; set; }
    public string? Token { get; set; }
    public DateTime RevokedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpirationTime { get; set; }
    public string? ReasonRevoked { get; set; }
    public string? UserId { get; set; }
    
    // 外键关系
    public virtual ApplicationUser? User { get; set; }
} 