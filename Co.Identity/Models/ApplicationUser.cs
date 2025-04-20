using Microsoft.AspNetCore.Identity;

namespace Co.Identity.Models;

public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
    public bool IsActive { get; set; } = true;
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
    
    // 新增字段，用于跟踪令牌刷新
    public int? TokenRefreshCount { get; set; }
    public DateTime? LastTokenRefreshAt { get; set; }
    public DateTime? LastPasswordChangedAt { get; set; }
    public bool TwoFactorEnabled { get; set; } = false;
    public DateTime? LastTwoFactorChangedAt { get; set; }
    
    // OTP/2FA相关字段
    public string? OtpSecretKey { get; set; }
    public bool OtpEnabled { get; set; } = false;
    public string? PreferredTwoFactorMethod { get; set; } // "app", "sms", "email"
    public DateTime? OtpSetupTime { get; set; }
    
    // 导航属性
    public virtual ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
    public virtual ICollection<RevokedToken> RevokedTokens { get; set; } = new List<RevokedToken>();
} 