namespace Co.Identity.Models;

public class AuditLog
{
    public int Id { get; set; }
    public string? UserId { get; set; }
    public string? Action { get; set; }
    public string? Details { get; set; }
    public string? ClientId { get; set; }
    public string? ClientIp { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    // 外键关系
    public virtual ApplicationUser? User { get; set; }
} 