using System.ComponentModel.DataAnnotations;

namespace Co.Identity.Models;

public class VerifyOtpModel
{
    [Required]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "验证码必须是6位数字")]
    public string OtpCode { get; set; } = string.Empty;
}

public class SetupSmsModel
{
    [Required]
    [Phone]
    public string PhoneNumber { get; set; } = string.Empty;
}

public class VerifySmsModel
{
    [Required]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "验证码必须是6位数字")]
    public string SmsCode { get; set; } = string.Empty;
} 