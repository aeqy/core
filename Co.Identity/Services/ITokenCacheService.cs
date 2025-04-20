namespace Co.Identity.Services;

public interface ITokenCacheService
{
    Task<bool> IsTokenRevokedAsync(string token);
    Task RevokeTokenAsync(string token, TimeSpan expiryTime);
    Task<string?> GetAccessTokenAsync(string refreshToken);
    Task SetAccessTokenAsync(string refreshToken, string accessToken, TimeSpan expiryTime);
} 