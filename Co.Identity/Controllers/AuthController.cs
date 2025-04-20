using Co.Identity.Models;
using Co.Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Co.Identity.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(
    IIdentityService identityService,
    ITokenCacheService tokenCacheService,
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

        var response = await identityService.LoginAsync(model.Username!, model.Password!);
        
        if (string.IsNullOrEmpty(response.AccessToken))
        {
            return Unauthorized(new { message = "用户名或密码不正确" });
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

        var response = await identityService.RefreshTokenAsync(model.RefreshToken!);
        
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