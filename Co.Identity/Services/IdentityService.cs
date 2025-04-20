using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Co.Identity.Data;
using Co.Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Co.Identity.Services;

public class IdentityService(
    UserManager<ApplicationUser> userManager,
    RoleManager<ApplicationRole> roleManager,
    IConfiguration configuration,
    ApplicationDbContext context,
    ILogger<IdentityService> logger)
    : IIdentityService
{
    private readonly RoleManager<ApplicationRole> _roleManager = roleManager;

    public async Task<TokenResponseModel> LoginAsync(string username, string password)
    {
        var user = await userManager.FindByNameAsync(username);
        if (user == null || !await userManager.CheckPasswordAsync(user, password))
        {
            return new TokenResponseModel();
        }

        // 更新最后登录时间
        user.LastLoginAt = DateTime.UtcNow;
        await userManager.UpdateAsync(user);

        // 获取用户角色
        var userRoles = await userManager.GetRolesAsync(user);

        // 创建令牌
        var accessToken = GenerateAccessToken(user, userRoles);
        var refreshToken = GenerateRefreshToken();

        // 保存刷新令牌
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); // 刷新令牌7天有效
        await userManager.UpdateAsync(user);

        // 返回令牌
        return new TokenResponseModel
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = 3600, // 访问令牌1小时有效
            TokenType = "Bearer",
            Scope = "openid profile email"
        };
    }

    public async Task<TokenResponseModel> RefreshTokenAsync(string refreshToken)
    {
        var user = await context.Users.SingleOrDefaultAsync(u => 
            u.RefreshToken == refreshToken && 
            u.RefreshTokenExpiryTime > DateTime.UtcNow);

        if (user == null)
        {
            return new TokenResponseModel();
        }

        // 获取用户角色
        var userRoles = await userManager.GetRolesAsync(user);

        // 创建新令牌
        var newAccessToken = GenerateAccessToken(user, userRoles);
        var newRefreshToken = GenerateRefreshToken();

        // 保存新刷新令牌
        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await userManager.UpdateAsync(user);

        // 返回新令牌
        return new TokenResponseModel
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            ExpiresIn = 3600, // 1小时
            TokenType = "Bearer",
            Scope = "openid profile email"
        };
    }

    public async Task<bool> RegisterAsync(RegisterModel model)
    {
        var userExists = await userManager.FindByEmailAsync(model.Email!);
        if (userExists != null)
        {
            return false;
        }

        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName,
            PhoneNumber = model.PhoneNumber,
            SecurityStamp = Guid.NewGuid().ToString()
        };

        var result = await userManager.CreateAsync(user, model.Password!);
        if (!result.Succeeded)
        {
            logger.LogError("用户创建失败: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }

        // 添加默认角色
        await userManager.AddToRoleAsync(user, "User");

        return true;
    }

    public async Task<bool> RevokeTokenAsync(string refreshToken)
    {
        var user = await context.Users.SingleOrDefaultAsync(u => u.RefreshToken == refreshToken);
        if (user == null)
        {
            return false;
        }

        // 撤销刷新令牌
        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        await userManager.UpdateAsync(user);

        return true;
    }

    public async Task<bool> ValidateTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(configuration["JWT:Secret"] ?? throw new InvalidOperationException("JWT密钥未配置"));

        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = configuration["JWT:ValidIssuer"],
                ValidateAudience = true,
                ValidAudience = configuration["JWT:ValidAudience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var userId = jwtToken.Claims.First(x => x.Type == "sub").Value;

            // 验证用户是否存在
            var user = await userManager.FindByIdAsync(userId);
            return user != null && user.IsActive;
        }
        catch
        {
            return false;
        }
    }

    private string GenerateAccessToken(ApplicationUser user, IList<string> roles)
    {
        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty)
        };

        // 添加角色声明
        foreach (var role in roles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, role));
        }

        // 添加自定义声明
        if (!string.IsNullOrEmpty(user.FirstName))
            authClaims.Add(new Claim("given_name", user.FirstName));
            
        if (!string.IsNullOrEmpty(user.LastName))
            authClaims.Add(new Claim("family_name", user.LastName));

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"] ?? throw new InvalidOperationException("JWT密钥未配置")));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = configuration["JWT:ValidIssuer"],
            Audience = configuration["JWT:ValidAudience"],
            Expires = DateTime.UtcNow.AddHours(1), // 令牌1小时后过期
            SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
            Subject = new ClaimsIdentity(authClaims)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
} 