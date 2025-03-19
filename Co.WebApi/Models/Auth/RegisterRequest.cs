using System.ComponentModel.DataAnnotations;

namespace Co.WebApi.Models.Auth;

/// <summary>
/// 注册请求模型
/// </summary>
public class RegisterRequest
{
    /// <summary>
    /// 电子邮箱
    /// </summary>
    [Required(ErrorMessage = "邮箱是必需的")]
    [EmailAddress(ErrorMessage = "邮箱格式不正确")]
    public string Email { get; set; }

    /// <summary>
    /// 密码
    /// </summary>
    [Required(ErrorMessage = "密码是必需的")]
    [StringLength(100, ErrorMessage = "密码长度必须至少为{2}个字符", MinimumLength = 6)]
    public string Password { get; set; }

    /// <summary>
    /// 确认密码
    /// </summary>
    [Compare("Password", ErrorMessage = "密码和确认密码不匹配")]
    public string ConfirmPassword { get; set; }
} 