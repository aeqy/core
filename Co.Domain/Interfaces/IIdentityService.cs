using System.Security.Claims;
using Co.Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace Co.Domain.Interfaces;

/// <summary>
/// 身份认证服务接口
/// </summary>
public interface IIdentityService
{
    /// <summary>
    /// 创建用户
    /// </summary>
    /// <param name="user">用户</param>
    /// <param name="password">密码</param>
    /// <param name="roles">角色列表</param>
    /// <returns>创建结果</returns>
    Task<(bool Succeeded, string[] Errors)> CreateUserAsync(IdentityUser<Guid> user, string password, IEnumerable<string> roles);

    /// <summary>
    /// 获取用户声明
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>用户声明列表</returns>
    Task<List<Claim>> GetUserClaimsAsync(string userId);

    /// <summary>
    /// 更新用户刷新令牌
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="refreshTokenExpiryTime">刷新令牌过期时间</param>
    /// <returns>任务</returns>
    Task<bool> UpdateUserRefreshTokenAsync(string userId, string refreshToken, DateTime refreshTokenExpiryTime);

    /// <summary>
    /// 验证用户密码
    /// </summary>
    /// <param name="username">用户名</param>
    /// <param name="password">密码</param>
    /// <returns>验证结果</returns>
    Task<(bool Succeeded, string UserId)> ValidateUserCredentialsAsync(string username, string password);

    /// <summary>
    /// 验证刷新令牌
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <returns>如果令牌有效则返回true</returns>
    Task<bool> ValidateRefreshTokenAsync(string refreshToken);

    /// <summary>
    /// 将访问令牌加入黑名单
    /// </summary>
    /// <param name="token">访问令牌</param>
    /// <param name="lifetime">黑名单保留时间</param>
    Task BlacklistAccessTokenAsync(string token, TimeSpan lifetime);

    /// <summary>
    /// 记录令牌吊销
    /// </summary>
    /// <param name="revocationLog">吊销日志</param>
    Task LogTokenRevocationAsync(TokenRevocationLog revocationLog);

    /// <summary>
    /// 记录用户注销
    /// </summary>
    /// <param name="logoutLog">注销日志</param>
    Task LogUserLogoutAsync(UserLogoutLog logoutLog);
}