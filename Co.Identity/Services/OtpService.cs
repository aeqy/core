using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Distributed;

namespace Co.Identity.Services;

public class OtpService : IOtpService
{
    private readonly IDistributedCache _cache;
    private readonly ILogger<OtpService> _logger;
    private readonly string _issuer;

    public OtpService(
        IDistributedCache cache,
        IConfiguration configuration,
        ILogger<OtpService> logger)
    {
        _cache = cache;
        _logger = logger;
        _issuer = configuration["JWT:ValidIssuer"] ?? "CoIdentityService";
    }

    public string GenerateOtpKey()
    {
        var key = new byte[20]; // 160 位
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(key);
        return Base32Encode(key);
    }

    public string GenerateOtpQrCodeUrl(string email, string secretKey)
    {
        var issuer = Uri.EscapeDataString(_issuer);
        var account = Uri.EscapeDataString(email);
        return $"otpauth://totp/{issuer}:{account}?secret={secretKey}&issuer={issuer}";
    }

    public bool VerifyOtpCode(string secretKey, string otpCode)
    {
        try
        {
            if (string.IsNullOrEmpty(secretKey) || string.IsNullOrEmpty(otpCode) || otpCode.Length != 6)
            {
                return false;
            }

            var keyBytes = Base32Decode(secretKey);
            var counter = GetCurrentCounter();
            
            // 验证当前和前后一个计数区间的代码，以处理时间轻微不同步
            return ValidateOtpInternal(keyBytes, counter - 1, otpCode) || 
                   ValidateOtpInternal(keyBytes, counter, otpCode) || 
                   ValidateOtpInternal(keyBytes, counter + 1, otpCode);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "OTP验证失败");
            return false;
        }
    }

    public string GenerateSmsCode()
    {
        // 生成6位数字验证码
        var random = new Random();
        return random.Next(100000, 999999).ToString();
    }

    public async Task CacheSmsCodeAsync(string phoneNumber, string code, int expiryMinutes = 5)
    {
        var key = $"sms:code:{phoneNumber}";
        await _cache.SetStringAsync(key, code, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(expiryMinutes)
        });
        
        _logger.LogInformation("为 {PhoneNumber} 缓存了验证码，有效期 {ExpiryMinutes} 分钟", phoneNumber, expiryMinutes);
    }

    public async Task<bool> VerifySmsCodeAsync(string phoneNumber, string code)
    {
        var key = $"sms:code:{phoneNumber}";
        var storedCode = await _cache.GetStringAsync(key);
        
        if (string.IsNullOrEmpty(storedCode) || storedCode != code)
        {
            _logger.LogWarning("短信验证码验证失败: {PhoneNumber}", phoneNumber);
            return false;
        }
        
        // 验证成功后删除缓存的验证码，避免重复使用
        await _cache.RemoveAsync(key);
        
        _logger.LogInformation("短信验证码验证成功: {PhoneNumber}", phoneNumber);
        return true;
    }

    #region 内部辅助方法

    private bool ValidateOtpInternal(byte[] key, long counter, string otpCode)
    {
        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(counterBytes);
        }
        
        // 确保8字节长度
        var paddedCounter = new byte[8];
        Array.Copy(counterBytes, paddedCounter, Math.Min(counterBytes.Length, 8));
        
        // 使用HMAC-SHA1生成OTP
        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(paddedCounter);
        
        // 计算偏移量
        var offset = hash[^1] & 0x0F;
        
        // 生成4字节的代码
        var truncatedHash = (hash[offset] & 0x7F) << 24 |
                            (hash[offset + 1] & 0xFF) << 16 |
                            (hash[offset + 2] & 0xFF) << 8 |
                            (hash[offset + 3] & 0xFF);
        
        // 截断为6位数字
        var hotp = truncatedHash % 1000000;
        
        return hotp.ToString("D6") == otpCode;
    }

    private long GetCurrentCounter()
    {
        // 使用TOTP算法，基于30秒时间步长
        return DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
    }

    private string Base32Encode(byte[] data)
    {
        // RFC 4648 Base32 字符集
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        
        var result = new StringBuilder();
        var bits = 0;
        var value = 0;
        
        for (var i = 0; i < data.Length; i++)
        {
            value = (value << 8) | data[i];
            bits += 8;
            
            while (bits >= 5)
            {
                bits -= 5;
                result.Append(alphabet[(value >> bits) & 0x1F]);
            }
        }
        
        if (bits > 0)
        {
            result.Append(alphabet[(value << (5 - bits)) & 0x1F]);
        }
        
        return result.ToString();
    }

    private byte[] Base32Decode(string input)
    {
        // RFC 4648 Base32 字符集
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        
        input = input.TrimEnd('=').ToUpper();
        var output = new List<byte>();
        var bits = 0;
        var value = 0;
        
        foreach (var c in input)
        {
            value = (value << 5) | alphabet.IndexOf(c);
            bits += 5;
            
            if (bits >= 8)
            {
                bits -= 8;
                output.Add((byte)((value >> bits) & 0xFF));
            }
        }
        
        return output.ToArray();
    }

    #endregion
} 