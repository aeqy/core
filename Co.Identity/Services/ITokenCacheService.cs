namespace Co.Identity.Services;

public interface ITokenCacheService
{
    Task<bool> IsTokenRevokedAsync(string token);
    Task RevokeTokenAsync(string token, TimeSpan expiryTime);
    Task<string?> GetAccessTokenAsync(string refreshToken);
    Task SetAccessTokenAsync(string refreshToken, string accessToken, TimeSpan expiryTime);
    
    // 两因素认证支持
    Task SetTwoFactorTokenAsync(string twoFactorToken, string userId, TimeSpan expiryTime);
    Task<string?> GetTwoFactorUserIdAsync(string twoFactorToken);
    Task RemoveTwoFactorTokenAsync(string twoFactorToken);
} 