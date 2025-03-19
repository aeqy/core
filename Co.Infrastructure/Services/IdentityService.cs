using System.Security.Claims;
using Co.Domain.Entities;
using Co.Domain.Interfaces;
using Co.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Co.Infrastructure.Services;

public class IdentityService(
    UserManager<IdentityUser<Guid>> userManager,
    RoleManager<IdentityRole<Guid>> roleManager,
    CoDbContext dbContext,
    ICacheService cache,
    ILogger<IdentityService> logger) : IIdentityService
{
    /// <summary>
    /// 创建用户
    /// </summary>
    /// <param name="user">用户</param>
    /// <param name="password">密码</param>
    /// <param name="roles">角色列表</param>
    /// <returns>结果</returns>
    public async Task<(bool Succeeded, string[] Errors)> CreateUserAsync(IdentityUser<Guid> user, string password,
        IEnumerable<string> roles)
    {
        try
        {
            var result = await userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                return (false, result.Errors.Select(e => e.Description).ToArray());
            }

            var enumerable = roles as string[] ?? roles.ToArray();
            if (enumerable.Any())
            {
                foreach (var role in enumerable)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        await roleManager.CreateAsync(new IdentityRole<Guid>(role));
                    }
                }

                result = await userManager.AddToRolesAsync(user, enumerable);
                if (!result.Succeeded)
                {
                    return (false, result.Errors.Select(e => e.Description).ToArray());
                }
            }

            return (true, Array.Empty<string>());
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "创建用户时发生错误: {Username}", user.UserName);
            throw;
        }
    }

    /// <summary>
    /// 获取用户声明
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>声明列表</returns>
    /// <exception cref="NotImplementedException"></exception>
    public async Task<List<Claim>> GetUserClaimsAsync(string userId)
    {
        try
        {
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out _))
                return new List<Claim>();

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
                return new List<Claim>();

            // 获取用户基本声明
            var claims = (await userManager.GetClaimsAsync(user)).ToList();

            // 获取用户角色并添加到声明中
            var roles = await userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
                // 同时添加OpenIddict标准格式的角色声明
                claims.Add(new Claim("role", role));
                claims.Add(new Claim("roles", role));
                claims.Add(new Claim("https://schemas.microsoft.com/ws/2008/06/identity/claims/role", role));

                // OpenIddict特定格式
                claims.Add(new Claim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Role, role));
            }

            // 添加用户ID和用户名基本声明
            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
            if (user.UserName != null)
            {
                claims.Add(new Claim(ClaimTypes.Name, user.UserName));


                // 增加兼容性 - 使用OpenIddict标准格式添加主要声明
                claims.Add(new Claim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject, user.Id.ToString()));
                claims.Add(new Claim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Name, user.UserName));
            }

            if (!string.IsNullOrEmpty(user.Email))
            {
                claims.Add(new Claim(ClaimTypes.Email, user.Email));
                claims.Add(new Claim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Email, user.Email));
            }

            logger.LogInformation("为用户 {UserId} 获取声明，包含 {ClaimCount} 个声明，角色: {Roles}",
                userId, claims.Count, string.Join(", ", roles));

            return claims;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "获取用户声明时发生错误: {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// 更新用户刷新令牌
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <param name="refreshToken"></param>
    /// <param name="refreshTokenExpiryTime">刷新令牌</param>
    /// <exception cref="NotImplementedException">刷新令牌过期时间</exception>
    public async Task<bool> UpdateUserRefreshTokenAsync(string userId, string refreshToken,
        DateTime refreshTokenExpiryTime)
    {
        try
        {
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out _))
                return false;

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
                return false;

            var refreshTokenClaim = new Claim("RefreshToken", refreshToken);
            var refreshTokenExpiryTimeClaim = new Claim("RefreshTokenExpiryTime", refreshTokenExpiryTime.ToString("o"));

            var existingClaims = await userManager.GetClaimsAsync(user);
            var existingRefreshTokenClaim = existingClaims.FirstOrDefault(c => c.Type == "RefreshToken");
            var existingRefreshTokenExpiryTimeClaim =
                existingClaims.FirstOrDefault(c => c.Type == "RefreshTokenExpiryTime");

            if (existingRefreshTokenClaim != null)
                await userManager.RemoveClaimAsync(user, existingRefreshTokenClaim);

            if (existingRefreshTokenExpiryTimeClaim != null)
                await userManager.RemoveClaimAsync(user, existingRefreshTokenExpiryTimeClaim);

            await userManager.AddClaimAsync(user, refreshTokenClaim);
            await userManager.AddClaimAsync(user, refreshTokenExpiryTimeClaim);

            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "更新用户刷新令牌时发生错误: {UserId}", userId);
            return false;
        }
    }

    /// <summary>
    /// 验证用户凭据
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    public async Task<(bool Succeeded, string UserId)> ValidateUserCredentialsAsync(string username, string password)
    {
        try
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                return (false, string.Empty);

            var user = await userManager.FindByNameAsync(username);
            if (user == null)
            {
                // 尝试通过电子邮件查找
                user = await userManager.FindByEmailAsync(username);
                if (user == null)
                    return (false, string.Empty);
            }

            // 验证密码
            var result = await userManager.CheckPasswordAsync(user, password);
            return result ? (true, user.Id.ToString()) : (false, string.Empty);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "验证用户凭据时发生错误: {Username}", username);
            return (false, string.Empty);
        }
    }

    public async Task<bool> ValidateRefreshTokenAsync(string refreshToken)
    {
        try
        {
            // 1. 先从缓存中检查令牌
            var cacheKey = $"refresh_token:{refreshToken}";
            var cachedToken = await cache.GetAsync<RefreshToken>(cacheKey);

            RefreshToken? tokenInfo;
            if (cachedToken != null)
            {
                tokenInfo = cachedToken;
                logger.LogDebug("从缓存中获取到刷新令牌");
            }
            else
            {
                // 2. 如果缓存中没有，从数据库获取
                tokenInfo = await dbContext.Set<RefreshToken>()
                    .FirstOrDefaultAsync(t => t.Token == refreshToken);

                if (tokenInfo != null)
                {
                    // 将令牌信息缓存，设置较短的过期时间（如5分钟）
                    await cache.SetAsync(cacheKey, tokenInfo, 300);
                    logger.LogDebug("刷新令牌已缓存");
                }
            }

            if (tokenInfo == null)
            {
                logger.LogWarning("未找到刷新令牌");
                return false;
            }

            // 3. 检查令牌是否过期
            if (tokenInfo.ExpiryTime <= DateTime.UtcNow)
            {
                logger.LogWarning("刷新令牌已过期");
                await cache.RemoveAsync(cacheKey);
                return false;
            }

            // 4. 检查令牌是否已被吊销
            var revokedKey = $"revoked_token:{refreshToken}";
            var blacklistEntry = await cache.GetAsync<TokenBlacklistEntry>(revokedKey);
            if (blacklistEntry?.IsBlacklisted == true)
            {
                logger.LogWarning("刷新令牌已被吊销");
                return false;
            }

            // 5. 检查用户状态
            var userCacheKey = $"user:{tokenInfo.UserId}";
            var user = await cache.GetOrCreateAsync(userCacheKey,
                async () => await dbContext.Set<IdentityUser<Guid>>()
                    .FindAsync(Guid.Parse(tokenInfo.UserId)),
                300); // 缓存5分钟

            if (user == null || !user.EmailConfirmed || user.LockoutEnd > DateTime.UtcNow)
            {
                logger.LogWarning("用户账户无效");
                return false;
            }


            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "验证刷新令牌时发生错误");
            return false;
        }
    }

    public async Task BlacklistAccessTokenAsync(string token, TimeSpan lifetime)
    {
        var blacklistKey = $"blacklisted_token:{token}";
        var blacklistEntry = new TokenBlacklistEntry();
        await cache.SetAsync(blacklistKey, blacklistEntry, (int)lifetime.TotalSeconds);
        logger.LogInformation("访问令牌已加入黑名单，有效期：{Lifetime}", lifetime);
    }

    public async Task LogTokenRevocationAsync(TokenRevocationLog revocationLog)
    {
        try
        {
            dbContext.Set<TokenRevocationLog>().Add(revocationLog);
            await dbContext.SaveChangesAsync();
            
            // 添加到黑名单缓存
            var blacklistKey = $"revoked_token:{revocationLog.TokenType}:{revocationLog.UserId}";
            var blacklistEntry = new TokenBlacklistEntry();
            await cache.SetAsync(blacklistKey, blacklistEntry, 3600); // 缓存1小时
            
            // 缓存吊销记录
            var cacheKey = $"revocation_log:{revocationLog.UserId}:{revocationLog.TokenType}";
            await cache.SetAsync(cacheKey, revocationLog, 3600); // 缓存1小时
            
            logger.LogInformation(
                "已记录令牌吊销：用户 {UserId}，类型 {TokenType}", 
                revocationLog.UserId, 
                revocationLog.TokenType
            );
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "记录令牌吊销失败");
        }
    }

    public async Task LogUserLogoutAsync(UserLogoutLog logoutLog)
    {
        try
        {
            dbContext.Set<UserLogoutLog>().Add(logoutLog);
            await dbContext.SaveChangesAsync();

            logger.LogInformation(
                "User logout logged for user {UserId}, type {LogoutType}",
                logoutLog.UserId,
                logoutLog.LogoutType
            );
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to log user logout");
        }
    }
}


