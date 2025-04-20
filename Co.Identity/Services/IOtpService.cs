namespace Co.Identity.Services;

public interface IOtpService
{
    /// <summary>
    /// 生成OTP密钥
    /// </summary>
    /// <returns>Base32编码的密钥</returns>
    string GenerateOtpKey();
    
    /// <summary>
    /// 生成OTP二维码URL(用于显示二维码)
    /// </summary>
    /// <param name="email">用户邮箱</param>
    /// <param name="secretKey">密钥</param>
    /// <returns>OTP验证器URL</returns>
    string GenerateOtpQrCodeUrl(string email, string secretKey);
    
    /// <summary>
    /// 验证OTP代码
    /// </summary>
    /// <param name="secretKey">密钥</param>
    /// <param name="otpCode">OTP代码</param>
    /// <returns>是否验证通过</returns>
    bool VerifyOtpCode(string secretKey, string otpCode);
    
    /// <summary>
    /// 生成短信验证码
    /// </summary>
    /// <returns>短信验证码</returns>
    string GenerateSmsCode();
    
    /// <summary>
    /// 缓存短信验证码
    /// </summary>
    /// <param name="phoneNumber">手机号</param>
    /// <param name="code">验证码</param>
    /// <param name="expiryMinutes">过期时间(分钟)</param>
    Task CacheSmsCodeAsync(string phoneNumber, string code, int expiryMinutes = 5);
    
    /// <summary>
    /// 验证短信验证码
    /// </summary>
    /// <param name="phoneNumber">手机号</param>
    /// <param name="code">验证码</param>
    /// <returns>是否验证通过</returns>
    Task<bool> VerifySmsCodeAsync(string phoneNumber, string code);
} 