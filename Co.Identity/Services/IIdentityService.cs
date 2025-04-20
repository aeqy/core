using Co.Identity.Models;

namespace Co.Identity.Services;

public interface IIdentityService
{
    Task<TokenResponseModel> LoginAsync(string username, string password);
    Task<TokenResponseModel> RefreshTokenAsync(string refreshToken);
    Task<bool> RegisterAsync(RegisterModel model);
    Task<bool> RevokeTokenAsync(string refreshToken);
    Task<bool> ValidateTokenAsync(string token);
    Task<TokenResponseModel> GenerateTokensAsync(ApplicationUser user, IList<string> roles);
} 