using System.ComponentModel.DataAnnotations;

namespace Co.Identity.Models;

public class VerifyTwoFactorModel
{
    [Required]
    public string TwoFactorToken { get; set; } = string.Empty;
    
    [Required]
    public string TwoFactorType { get; set; } = string.Empty; // "app" 或 "sms"
    
    [Required]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "验证码必须是6位数字")]
    public string Code { get; set; } = string.Empty;
} 