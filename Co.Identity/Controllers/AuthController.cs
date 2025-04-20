using Co.Identity.Data;
using Co.Identity.Models;
using Co.Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Co.Identity.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(
    IIdentityService identityService,
    ITokenCacheService tokenCacheService,
    UserManager<ApplicationUser> userManager,
    ApplicationDbContext context,
    ILogger<AuthController> logger)
    : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await userManager.FindByNameAsync(model.Username);
        if (user == null || !(await userManager.CheckPasswordAsync(user, model.Password)))
        {
            return Unauthorized(new { message = "用户名或密码错误" });
        }

        // 添加审计日志
        await context.AuditLogs.AddAsync(new AuditLog
        {
            UserId = user.Id,
            Action = "Login.Password",
            Timestamp = DateTime.UtcNow,
            ClientIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
            Details = "用户密码验证成功"
        });
        
        await context.SaveChangesAsync();

        // 检查是否需要两因素认证
        if (user.TwoFactorEnabled)
        {
            // 生成两因素认证令牌，用于后续验证
            var twoFactorToken = Guid.NewGuid().ToString();
            
            // 缓存两因素认证令牌，关联到用户ID，有效期5分钟
            await tokenCacheService.SetTwoFactorTokenAsync(twoFactorToken, user.Id, TimeSpan.FromMinutes(5));
            
            // 根据用户首选的两因素认证方式，执行不同的操作
            if (user.PreferredTwoFactorMethod == "app" && user.OtpEnabled)
            {
                return Ok(new
                {
                    requiresTwoFactor = true,
                    twoFactorToken = twoFactorToken,
                    twoFactorType = "app"
                });
            }
            else if (user.PreferredTwoFactorMethod == "sms" && !string.IsNullOrEmpty(user.PhoneNumber))
            {
                // 生成短信验证码
                var otpService = HttpContext.RequestServices.GetRequiredService<IOtpService>();
                var smsCode = otpService.GenerateSmsCode();
                
                // 缓存验证码
                await otpService.CacheSmsCodeAsync(user.PhoneNumber, smsCode);
                
                // 在实际环境中，这里应该发送短信
                // 为了演示，我们仅记录日志
                logger.LogInformation("为用户 {UserId} 生成的短信验证码: {SmsCode}", user.Id, smsCode);
                
                return Ok(new
                {
                    requiresTwoFactor = true,
                    twoFactorToken = twoFactorToken,
                    twoFactorType = "sms",
                    phoneNumber = user.PhoneNumber.Length > 8 ? 
                        user.PhoneNumber[..4] + "****" + user.PhoneNumber[^4..] : // 掩码手机号
                        "****" // 极短号码的情况
                });
            }
        }

        // 如果未启用两因素认证或不符合条件，直接生成令牌
        var response = await identityService.LoginAsync(model.Username, model.Password);
        
        if (string.IsNullOrEmpty(response.AccessToken))
        {
            return Unauthorized(new { message = "登录失败" });
        }

        // 缓存访问令牌
        if (!string.IsNullOrEmpty(response.RefreshToken))
        {
            await tokenCacheService.SetAccessTokenAsync(
                response.RefreshToken, 
                response.AccessToken, 
                TimeSpan.FromSeconds(response.ExpiresIn));
        }

        return Ok(response);
    }

    [HttpPost("verify-2fa")]
    public async Task<IActionResult> VerifyTwoFactor([FromBody] VerifyTwoFactorModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // 验证两因素认证令牌
        var userId = await tokenCacheService.GetTwoFactorUserIdAsync(model.TwoFactorToken);
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized(new { message = "无效的两因素认证令牌或已过期" });
        }

        // 查找用户
        var user = await userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return Unauthorized(new { message = "用户不存在" });
        }

        bool isValid = false;
        
        // 根据不同的两因素认证类型验证
        if (model.TwoFactorType == "app" && user.OtpEnabled)
        {
            // 验证应用验证器代码
            var otpService = HttpContext.RequestServices.GetRequiredService<IOtpService>();
            isValid = otpService.VerifyOtpCode(user.OtpSecretKey, model.Code);
        }
        else if (model.TwoFactorType == "sms" && !string.IsNullOrEmpty(user.PhoneNumber))
        {
            // 验证短信验证码
            var otpService = HttpContext.RequestServices.GetRequiredService<IOtpService>();
            isValid = await otpService.VerifySmsCodeAsync(user.PhoneNumber, model.Code);
        }

        if (!isValid)
        {
            // 添加审计日志
            await context.AuditLogs.AddAsync(new AuditLog
            {
                UserId = user.Id,
                Action = "Login.TwoFactorFailed",
                Timestamp = DateTime.UtcNow,
                ClientIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
                Details = $"两因素认证失败，类型: {model.TwoFactorType}"
            });
            
            await context.SaveChangesAsync();
            
            return Unauthorized(new { message = "验证码无效" });
        }

        // 添加审计日志
        await context.AuditLogs.AddAsync(new AuditLog
        {
            UserId = user.Id,
            Action = "Login.TwoFactorSuccess",
            Timestamp = DateTime.UtcNow,
            ClientIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
            Details = $"两因素认证成功，类型: {model.TwoFactorType}"
        });
        
        await context.SaveChangesAsync();

        // 删除两因素认证令牌
        await tokenCacheService.RemoveTwoFactorTokenAsync(model.TwoFactorToken);

        // 生成访问令牌
        var userRoles = await userManager.GetRolesAsync(user);
        var tokenResponse = await identityService.GenerateTokensAsync(user, userRoles);

        // 缓存访问令牌
        if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
        {
            await tokenCacheService.SetAccessTokenAsync(
                tokenResponse.RefreshToken, 
                tokenResponse.AccessToken, 
                TimeSpan.FromSeconds(tokenResponse.ExpiresIn));
        }

        return Ok(tokenResponse);
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var result = await identityService.RegisterAsync(model);
        
        if (!result)
        {
            return BadRequest(new { message = "用户注册失败" });
        }

        return Ok(new { message = "用户注册成功" });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var response = await identityService.RefreshTokenAsync(model.RefreshToken);
        
        if (string.IsNullOrEmpty(response.AccessToken))
        {
            return Unauthorized(new { message = "刷新令牌无效或已过期" });
        }

        // 缓存新的访问令牌
        if (!string.IsNullOrEmpty(response.RefreshToken))
        {
            await tokenCacheService.SetAccessTokenAsync(
                response.RefreshToken, 
                response.AccessToken, 
                TimeSpan.FromSeconds(response.ExpiresIn));
        }

        return Ok(response);
    }

    [Authorize]
    [HttpPost("revoke-token")]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenModel model)
    {
        if (string.IsNullOrEmpty(model.RefreshToken))
        {
            return BadRequest(new { message = "刷新令牌不能为空" });
        }

        var result = await identityService.RevokeTokenAsync(model.RefreshToken);
        
        if (!result)
        {
            return BadRequest(new { message = "刷新令牌撤销失败" });
        }

        // 将访问令牌标记为已撤销
        var accessToken = await tokenCacheService.GetAccessTokenAsync(model.RefreshToken);
        if (!string.IsNullOrEmpty(accessToken))
        {
            await tokenCacheService.RevokeTokenAsync(accessToken, TimeSpan.FromHours(1));
        }

        return Ok(new { message = "令牌已成功撤销" });
    }

    [Authorize]
    [HttpGet("validate-token")]
    public async Task<IActionResult> ValidateToken()
    {
        var authHeader = HttpContext.Request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        {
            return Unauthorized(new { message = "未提供授权令牌" });
        }

        var token = authHeader.Substring("Bearer ".Length).Trim();
        
        // 检查令牌是否被撤销
        if (await tokenCacheService.IsTokenRevokedAsync(token))
        {
            return Unauthorized(new { message = "令牌已被撤销" });
        }

        var isValid = await identityService.ValidateTokenAsync(token);
        
        if (!isValid)
        {
            return Unauthorized(new { message = "令牌无效或已过期" });
        }

        return Ok(new { message = "令牌有效" });
    }
} 