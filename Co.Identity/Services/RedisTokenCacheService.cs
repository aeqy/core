using Co.Identity.Config;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace Co.Identity.Services;

public class RedisTokenCacheService(
    IDistributedCache cache,
    IOptions<HybridCacheOptions> options)
    : ITokenCacheService
{
    private readonly string _keyPrefix = options.Value.KeyPrefix;

    public async Task<bool> IsTokenRevokedAsync(string token)
    {
        var key = $"{_keyPrefix}revoked:{token}";
        var value = await cache.GetStringAsync(key);
        return !string.IsNullOrEmpty(value);
    }

    public async Task RevokeTokenAsync(string token, TimeSpan expiryTime)
    {
        var key = $"{_keyPrefix}revoked:{token}";
        await cache.SetStringAsync(key, "revoked", new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = expiryTime
        });
    }

    public async Task<string?> GetAccessTokenAsync(string refreshToken)
    {
        var key = $"{_keyPrefix}token:{refreshToken}";
        return await cache.GetStringAsync(key);
    }

    public async Task SetAccessTokenAsync(string refreshToken, string accessToken, TimeSpan expiryTime)
    {
        var key = $"{_keyPrefix}token:{refreshToken}";
        await cache.SetStringAsync(key, accessToken, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = expiryTime
        });
    }
} 