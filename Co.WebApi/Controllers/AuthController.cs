using System.Collections.Immutable;
using System.Security.Claims;
using Co.Domain.Entities;
using Co.Domain.Interfaces;
using Co.WebApi.Models.Auth;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using RegisterRequest = Co.WebApi.Models.Auth.RegisterRequest;

namespace Co.WebApi.Controllers;

/// <summary>
/// 表示身份验证过程中发生的异常。
/// </summary>
public class AuthenticationException : Exception
{
    /// <summary>
    /// 获取错误代码。
    /// </summary>
    public string ErrorCode { get; }

    /// <summary>
    /// 初始化 AuthenticationException 类的新实例。
    /// </summary>
    /// <param name="errorCode">错误代码。</param>
    /// <param name="message">错误消息。</param>
    public AuthenticationException(string errorCode, string message) : base(message)
    {
        ErrorCode = errorCode;
    }
}

/// <summary>
/// 认证控制器
/// </summary>
[ApiController]
[Route("connect")]
public class AuthController : ControllerBase
{
    private readonly IIdentityService _identityService;
    private readonly UserManager<IdentityUser<Guid>> _userManager;
    private readonly SignInManager<IdentityUser<Guid>> _signInManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<AuthController> _logger;
    private readonly IOptions<OpenIddictServerOptions> _openIddictServerOptions;


    /// <summary>
    /// 构造函数
    /// </summary>
    public AuthController(
        IIdentityService identityService,
        UserManager<IdentityUser<Guid>> userManager,
        SignInManager<IdentityUser<Guid>> signInManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        IOptions<OpenIddictServerOptions> openIddictServerOptions,
        ILogger<AuthController> logger)
    {
        _identityService = identityService;
        _userManager = userManager;
        _signInManager = signInManager;
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _logger = logger;
        _openIddictServerOptions = openIddictServerOptions;
    }

    /// <summary>
    /// 获取Token (OpenIddict token endpoint)
    /// </summary>
    /// <returns>认证结果</returns>
    [HttpPost("token")]
    // [Produces("application/json")]
    [AllowAnonymous]
    public async Task<IActionResult> Token()
    {
        try
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new AuthenticationException("invalid_request",
                              ("The OpenID Connect request is missing."));

            if (request.IsPasswordGrantType())
            {
                return await HandlePasswordGrantTypeAsync(request);
            }
            else if (request.IsRefreshTokenGrantType())
            {
                return await HandleRefreshTokenGrantTypeAsync(request);
            }
            else if (request.IsClientCredentialsGrantType())
            {
                return await HandleClientCredentialsGrantTypeAsync(request);
            }

            return BadRequest(new ErrorResponse
                { Error = "unsupported_grant_type", ErrorDescription = "The specified grant type is not supported." });
        }
        catch (AuthenticationException ex)
        {
            _logger.LogWarning(ex, "Authentication error: {ErrorCode} - {Message}", ex.ErrorCode, ex.Message);
            return BadRequest(new ErrorResponse { Error = ex.ErrorCode, ErrorDescription = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unexpected error occurred during token processing.");
            return StatusCode(StatusCodes.Status500InternalServerError,
                new ErrorResponse { Error = "server_error", ErrorDescription = "An internal server error occurred." });
        }
    }

    /// <summary>
    /// 注册用户
    /// </summary>
    /// <param name="model">注册模型</param>
    /// <returns>注册结果</returns>
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterRequest model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = new IdentityUser<Guid>
        {
            UserName = model.Email,
            Email = model.Email,
            // FirstName = model.FirstName,
            // LastName = model.LastName,
            // PhoneNumber = model.PhoneNumber,
            EmailConfirmed = true, // 在生产环境中，应通过邮件确认
            PhoneNumberConfirmed = true // 在生产环境中，应通过短信确认
        };

        var result = await _identityService.CreateUserAsync(user, model.Password, new List<string> { "User" });

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error);
            }

            return BadRequest(ModelState);
        }

        _logger.LogInformation("用户 {Email} 注册成功", model.Email);
        return Ok(new { message = "注册成功" });
    }
    
    /// <summary>
    /// 获取当前用户信息 (userinfo endpoint).
    /// </summary>
    /// <returns>用户信息。</returns>
    [HttpGet("userinfo")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized, Type = typeof(ErrorResponse))]
    public async Task<IActionResult> Userinfo()
    {
        _logger.LogInformation("Userinfo request received.  URL: {RequestUrl}", Request.GetDisplayUrl());

        var userId = User.FindFirstValue(OpenIddictConstants.Claims.Subject) ??  User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("Userinfo request failed:  User ID not found in token.");
            return Unauthorized(new ErrorResponse { Error = "invalid_token", ErrorDescription = "The provided token is invalid." });
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("Userinfo request failed:  User not found for ID: {UserId}", userId);
            return Unauthorized(new ErrorResponse { Error = "invalid_token", ErrorDescription = "The provided token is invalid." }); // 401
        }


        var claims = new Dictionary<string, object>
        {
            [Claims.Subject] = user.Id.ToString()
        };

        if (User.HasScope(Scopes.Email))
        {
            if (user.Email != null) claims[Claims.Email] = user.Email;
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }
        else
        {
            // 始终返回邮箱信息
            if (user.Email != null) claims[Claims.Email] = user.Email;
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (User.HasScope(Scopes.Profile))
        {
            if (user.UserName != null) claims[Claims.PreferredUsername] = user.UserName;
        }
        else
        {
            // 始终返回用户名
            if (user.UserName != null) claims[Claims.PreferredUsername] = user.UserName;
        }

        if (User.HasScope(Scopes.Phone) && !string.IsNullOrEmpty(user.PhoneNumber))
        {
            claims[Claims.PhoneNumber] = user.PhoneNumber;
            claims[Claims.PhoneNumberVerified] = user.PhoneNumberConfirmed;
        }
        else if(user.PhoneNumber != null)
        {
            claims[Claims.PhoneNumber] = user.PhoneNumber;
            claims[Claims.PhoneNumberVerified] = user.PhoneNumberConfirmed;
        }

        // 获取用户角色
        var roles = await _userManager.GetRolesAsync(user);
        if (roles.Any())
        {
            claims["roles"] = roles;  // 使用 "roles" 作为键
        }

        _logger.LogInformation("Userinfo request successful for user ID: {UserId}", userId);
        return Ok(claims);
    }

    /// <summary>
    /// 吊销令牌 (logout/revoke endpoint)
    /// </summary>
    [HttpPost("logout"), HttpPost("revoke")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest, Type = typeof(ErrorResponse))]
    [ProducesResponseType(StatusCodes.Status401Unauthorized, Type = typeof(ErrorResponse))]
    [ProducesResponseType(StatusCodes.Status403Forbidden, Type = typeof(ErrorResponse))]
    [ProducesResponseType(StatusCodes.Status500InternalServerError, Type = typeof(ErrorResponse))]
    public async Task<IActionResult> Revoke()
    {
        try
        {
            // 获取OpenIddict请求
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new AuthenticationException("invalid_request", "The revocation request is invalid.");

            // 获取当前认证结果
            var authentication =
                await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (!authentication.Succeeded)
            {
                _logger.LogWarning("Token authentication failed during revocation");
                return Unauthorized(new ErrorResponse
                {
                    Error = "invalid_token",
                    ErrorDescription = "The provided token is invalid or has expired."
                });
            }

            // 获取当前用户信息
            var currentUserId = User.FindFirstValue(Claims.Subject) ??
                                User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(currentUserId))
            {
                _logger.LogWarning("Unable to extract user identifier from the current principal");
                return Unauthorized(new ErrorResponse
                {
                    Error = "invalid_token",
                    ErrorDescription = "The authentication token is invalid."
                });
            }

            // 获取要吊销的令牌
            var tokenToRevoke = request.Token ?? request.AccessToken ?? request.RefreshToken;
            if (string.IsNullOrEmpty(tokenToRevoke))
            {
                _logger.LogWarning("No token provided for revocation");
                return BadRequest(new ErrorResponse
                {
                    Error = "invalid_request",
                    ErrorDescription = "The token to revoke was not provided."
                });
            }

            // 令牌安全哈希（用于日志）
            var tokenHash = Convert.ToBase64String(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(tokenToRevoke)
                )
            );
            _logger.LogInformation("Processing revocation request for token hash: {TokenHash}", tokenHash);

            // 验证令牌并获取其主体
            ClaimsPrincipal? tokenPrincipal;
            try
            {
                var result =
                    await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                tokenPrincipal = result?.Principal;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while authenticating token");
                return BadRequest(new ErrorResponse
                {
                    Error = "invalid_token",
                    ErrorDescription = "The provided token is invalid."
                });
            }

            if (tokenPrincipal == null)
            {
                _logger.LogWarning("Unable to validate the provided token");
                return BadRequest(new ErrorResponse
                {
                    Error = "invalid_token",
                    ErrorDescription = "The provided token could not be validated."
                });
            }

            // 获取令牌所属用户ID
            var tokenUserId = tokenPrincipal.FindFirstValue(Claims.Subject) ??
                              tokenPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);

            // 检查权限
            var isAdmin = User.IsInRole("Administrator");
            if (!isAdmin && tokenUserId != currentUserId)
            {
                _logger.LogWarning("User {CurrentUserId} attempted to revoke token belonging to user {TokenUserId}",
                    currentUserId, tokenUserId);
                return StatusCode(StatusCodes.Status403Forbidden,
                    new ErrorResponse
                    {
                        Error = "insufficient_permissions",
                        ErrorDescription = "You don't have permission to revoke this token."
                    });
            }

            // 获取令牌类型
            var tokenType = request.TokenTypeHint;
            if (string.IsNullOrEmpty(tokenType))
            {
                // 尝试确定令牌类型
                tokenType = await DetermineTokenTypeAsync(tokenToRevoke);
            }

            // 执行令牌吊销
            var revocationResult = await RevokeTokenAsync(tokenUserId!, tokenToRevoke, tokenType);
            if (!revocationResult.Succeeded)
            {
                _logger.LogError("Token revocation failed: {Error}", revocationResult.Error);
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new ErrorResponse
                    {
                        Error = "revocation_failed",
                        ErrorDescription = revocationResult.Error
                    });
            }

            // 发送注销通知（如果是logout请求）
            if (Request.Path.Value?.EndsWith("/logout", StringComparison.OrdinalIgnoreCase) == true)
            {
                await SendLogoutNotificationAsync(tokenUserId!);
            }

            // 清除相关cookie（如果有）
            await ClearAuthenticationCookiesAsync();

            // 返回成功响应
            var response = new
            {
                message = "Token successfully revoked",
                timestamp = DateTimeOffset.UtcNow,
                tokenType = tokenType ?? "unknown",
                logoutInitiated = Request.Path.Value?.EndsWith("/logout") == true
            };

            _logger.LogInformation(
                "Token revocation successful. Type: {TokenType}, User: {UserId}, TokenHash: {TokenHash}",
                tokenType ?? "unknown", tokenUserId, tokenHash);

            return Ok(response);
        }
        catch (AuthenticationException ex)
        {
            _logger.LogWarning(ex, "Authentication error during token revocation");
            return BadRequest(new ErrorResponse
            {
                Error = ex.ErrorCode,
                ErrorDescription = ex.Message
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token revocation");
            return StatusCode(StatusCodes.Status500InternalServerError,
                new ErrorResponse
                {
                    Error = "server_error",
                    ErrorDescription = "An unexpected error occurred while processing the request."
                });
        }
    }

    /// <summary>
    /// 确定令牌类型
    /// </summary>
    private async Task<string?> DetermineTokenTypeAsync(string token)
    {
        try
        {
            // 尝试作为访问令牌验证
            var accessTokenResult = await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (accessTokenResult?.Succeeded == true)
            {
                return OpenIddictConstants.TokenTypeHints.AccessToken;
            }

            // 尝试作为刷新令牌验证
            // 注意：这需要自定义实现，因为OpenIddict默认不支持直接验证刷新令牌
            if (await _identityService.ValidateRefreshTokenAsync(token))
            {
                return OpenIddictConstants.TokenTypeHints.RefreshToken;
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 吊销令牌
    /// </summary>
    private async Task<(bool Succeeded, string? Error)> RevokeTokenAsync(
        string userId,
        string token,
        string? tokenType)
    {
        try
        {
            switch (tokenType)
            {
                case TokenTypeHints.AccessToken:
                    // 将访问令牌添加到黑名单
                    await _identityService.BlacklistAccessTokenAsync(token, TimeSpan.FromHours(1));
                    break;

                case TokenTypeHints.RefreshToken:
                    // 吊销刷新令牌
                    await _identityService.UpdateUserRefreshTokenAsync(userId, null!, DateTime.UtcNow);
                    break;

                default:
                    // 如果不确定类型，执行所有吊销操作
                    await _identityService.BlacklistAccessTokenAsync(token, TimeSpan.FromHours(1));
                    await _identityService.UpdateUserRefreshTokenAsync(userId, null!, DateTime.UtcNow);
                    break;
            }

            // 可选：记录吊销事件
            await _identityService.LogTokenRevocationAsync(new TokenRevocationLog
            {
                UserId = userId,
                TokenType = tokenType ?? "unknown",
                RevokedAt = DateTime.UtcNow,
                Reason = "explicit_revocation"
            });

            return (true, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while revoking token");
            return (false, "Failed to revoke token: " + ex.Message);
        }
    }

    /// <summary>
    /// 发送注销通知
    /// </summary>
    private async Task SendLogoutNotificationAsync(string userId)
    {
        try
        {
            // 示例：通过 SignalR 发送注销通知
            // await _hubContext.Clients.User(userId).SendAsync("ForceLogout");

            // 示例：记录注销事件
            await _identityService.LogUserLogoutAsync(new UserLogoutLog
            {
                UserId = userId,
                LogoutTime = DateTime.UtcNow,
                LogoutType = "explicit",
                InitiatedBy = User.FindFirstValue(Claims.Subject) ?? "unknown"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending logout notification for user {UserId}", userId);
        }
    }

    /// <summary>
    /// 清除认证Cookie
    /// </summary>
    private async Task ClearAuthenticationCookiesAsync()
    {
        // 清除认证Cookie
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // 清除其他相关Cookie
        foreach (var cookie in Request.Cookies.Keys)
        {
            if (cookie.StartsWith(".AspNetCore.") || cookie.StartsWith("Identity."))
            {
                Response.Cookies.Delete(cookie);
            }
        }
    }

    #region 私有方法

    /// <summary>
    /// 处理密码授权类型
    /// </summary>
    private async Task<IActionResult> HandlePasswordGrantTypeAsync(OpenIddictRequest request)
    {
        _logger.LogInformation("Handling password grant type for user: {Username}", request.Username);

        if (request.Username != null)
        {
            var user = await _userManager.FindByNameAsync(request.Username);
            if (user == null)
            {
                _logger.LogWarning("Authentication failed for username: {Username}. User not found.", request.Username);
                throw new AuthenticationException("invalid_grant", "Invalid username or password.");
            }

            if (request.Password != null)
            {
                var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
                if (!result.Succeeded)
                {
                    if (result.IsLockedOut)
                    {
                        _logger.LogWarning("Authentication failed for username: {Username}. Account locked out.",
                            request.Username);
                        throw new AuthenticationException("invalid_grant", "Account locked out.");
                    }

                    if (result.IsNotAllowed)
                    {
                        _logger.LogWarning("Authentication failed for username: {Username}. Account not allowed.",
                            request.Username);
                        throw new AuthenticationException("invalid_grant", "Account not allowed to sign in.");
                    }

                    _logger.LogWarning("Authentication failed for username: {Username}. Invalid password.",
                        request.Username);
                    throw new AuthenticationException("invalid_grant", "Invalid username or password.");
                }
            }

            // 检查 DNT 头 (可选)
            if (Request.Headers.ContainsKey("DNT") && Request.Headers["DNT"] == "1")
            {
                _logger.LogInformation("DNT header detected.  Respecting user's tracking preference.");
                // 在此可以添加逻辑来限制跟踪，但这通常在应用程序的其他部分处理
            }

            return await CreateAuthenticationTicketAsync(user, request.GetScopes());
        }

        return await HandleClientCredentialsGrantTypeAsync(request);
    }

    /// <summary>
    /// 处理刷新令牌授权类型
    /// </summary>
    private async Task<IActionResult> HandleRefreshTokenGrantTypeAsync(OpenIddictRequest request)
    {
        _logger.LogInformation("Handling refresh token grant type.");

        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result?.Principal == null)
        {
            _logger.LogWarning("Refresh token validation failed.");
            throw new AuthenticationException("invalid_grant", "The refresh token is invalid or has expired.");
        }

        var userId = result.Principal.FindFirstValue(ClaimTypes.NameIdentifier) ??
                     result.Principal.FindFirstValue(OpenIddictConstants.Claims.Subject);
        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("Refresh token does not contain a user ID.");
            throw new AuthenticationException("invalid_grant", "The refresh token is invalid.");
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("User not found for refresh token. User ID: {UserId}", userId);
            throw new AuthenticationException("invalid_grant", "The refresh token is invalid.");
        }

        // 检查用户状态（示例）
        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            _logger.LogWarning("User account is not confirmed for refresh token. User ID: {UserId}", userId);
            throw new AuthenticationException("invalid_grant", "User account is not confirmed");
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            _logger.LogWarning("User account is locked out for refresh token. User ID: {UserId}", userId);
            throw new AuthenticationException("invalid_grant", "User account is locked out");
        }

        // Refresh Token Rotation: 生成新的刷新令牌
        var newRefreshToken = Guid.NewGuid().ToString();
        var newRefreshTokenExpiryTime = DateTime.UtcNow.AddDays(30);

        // 使旧的刷新令牌失效 (这里假设您有一个地方存储和管理刷新令牌)
        await _identityService.UpdateUserRefreshTokenAsync(userId, newRefreshToken,
            newRefreshTokenExpiryTime); // 更新数据库中的刷新令牌

        return await CreateAuthenticationTicketAsync(user, request.GetScopes(), newRefreshToken,
            newRefreshTokenExpiryTime);
    }

    /// <summary>
    /// 创建并返回认证票据（Authentication Ticket）
    /// </summary>
    /// <param name="user">用户对象</param>
    /// <param name="scopes">请求的作用域</param>
    /// <param name="newRefreshToken">新的刷新令牌（可选）</param>
    /// <param name="newRefreshTokenExpiryTime">新的刷新令牌过期时间（可选）</param>
    /// <returns>包含认证信息的SignInResult</returns>
    private async Task<IActionResult> CreateAuthenticationTicketAsync(
        IdentityUser<Guid> user,
        ImmutableArray<string> scopes,
        string? newRefreshToken = null,
        DateTime? newRefreshTokenExpiryTime = null)
    {
        try
        {
            _logger.LogInformation("开始为用户 {UserId} 创建认证票据，请求的作用域: {Scopes}",
                user.Id, string.Join(", ", scopes));

            // 获取用户Claims (通过身份服务)
            var userClaims = await _identityService.GetUserClaimsAsync(user.Id.ToString());
            _logger.LogDebug("获取到用户 {UserId} 的声明 {ClaimsCount} 个", user.Id, userClaims.Count);

            // 确保包含Subject声明
            if (userClaims.All(c => c.Type != OpenIddictConstants.Claims.Subject))
            {
                userClaims.Add(new Claim(OpenIddictConstants.Claims.Subject, user.Id.ToString()));
            }

            // 获取并添加用户角色
            var roles = await _userManager.GetRolesAsync(user);
            _logger.LogDebug("用户 {UserId} 拥有的角色: {Roles}", user.Id, string.Join(", ", roles));

            foreach (var role in roles)
            {
                // 添加三种可能的角色声明格式，确保兼容性
                userClaims.Add(new Claim(OpenIddictConstants.Claims.Role, role));
                userClaims.Add(new Claim(ClaimTypes.Role, role));
                userClaims.Add(new Claim("role", role));
            }

            // 创建Claims身份
            var identity = new ClaimsIdentity(
                userClaims,
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                OpenIddictConstants.Claims.Name,
                OpenIddictConstants.Claims.Role);

            // 创建主体
            var principal = new ClaimsPrincipal(identity);

            // 设置作用域和资源
            principal.SetScopes(scopes);
            principal.SetResources(await _scopeManager.ListResourcesAsync(scopes).ToListAsync());

            // 处理刷新令牌
            // 两种情况：1. 外部提供刷新令牌(令牌轮换) 2. 作用域包含offline_access(初始生成)
            if (!string.IsNullOrEmpty(newRefreshToken))
            {
                _logger.LogDebug("为用户 {UserId} 设置提供的刷新令牌，过期时间: {ExpiryTime}",
                    user.Id, newRefreshTokenExpiryTime);

                principal.SetRefreshTokenLifetime(_openIddictServerOptions.Value.RefreshTokenLifetime);
            }
            else if (scopes.Contains(OpenIddictConstants.Scopes.OfflineAccess))
            {
                // 生成新的刷新令牌
                newRefreshToken = Guid.NewGuid().ToString();
                newRefreshTokenExpiryTime = DateTime.UtcNow.AddDays(30);

                _logger.LogDebug("为用户 {UserId} 生成新的刷新令牌，过期时间: {ExpiryTime}",
                    user.Id, newRefreshTokenExpiryTime);

                // 存储刷新令牌
                await _identityService.UpdateUserRefreshTokenAsync(
                    user.Id.ToString(), newRefreshToken, newRefreshTokenExpiryTime.Value);

                principal.SetRefreshTokenLifetime(TimeSpan.FromDays(30));
            }

            // 为不同的令牌类型设置目标 (关键步骤，确保声明正确分配)
            foreach (var claim in principal.Claims)
            {
                // 如果声明已经由OpenIddict设置了目标，跳过
                // if (_openIddictServerOptions.Value.DestinationService.GetDestinations(claim).Any())
                // {
                //     continue;
                // }
                var destinations = claim.GetDestinations();
                if (destinations != null && destinations.Any())
                {
                    continue; // 如果声明已经设置了目标，跳过
                }

                // 根据声明类型设置目标
                switch (claim.Type)
                {
                    // 用户信息相关声明 - 访问令牌和身份令牌
                    case OpenIddictConstants.Claims.Name:
                    case OpenIddictConstants.Claims.GivenName:
                    case OpenIddictConstants.Claims.FamilyName:
                    case OpenIddictConstants.Claims.Email:
                    case OpenIddictConstants.Claims.EmailVerified:
                    case OpenIddictConstants.Claims.PhoneNumber:
                    case OpenIddictConstants.Claims.PhoneNumberVerified:
                    case OpenIddictConstants.Claims.PreferredUsername:
                        claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken,
                            OpenIddictConstants.Destinations.IdentityToken);
                        break;

                    // 主体标识 - 所有令牌
                    case OpenIddictConstants.Claims.Subject:
                        claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken,
                            OpenIddictConstants.Destinations.IdentityToken,
                            "refresh_token");
                        break;

                    // 角色声明 - 访问令牌和身份令牌
                    case OpenIddictConstants.Claims.Role:
                        claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken,
                            OpenIddictConstants.Destinations.IdentityToken);
                        break;

                    case ClaimTypes.Role:
                        claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken,
                            OpenIddictConstants.Destinations.IdentityToken);
                        break;

                    // 作用域声明 - 访问令牌
                    case OpenIddictConstants.Claims.Scope:
                        claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
                        break;

                    // 其他所有声明默认添加到访问令牌
                    default:
                        claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
                        break;
                }
            }

            // 创建认证票据并设置过期时间
            var ticket = new AuthenticationTicket(
                principal,
                new AuthenticationProperties(),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // 设置访问令牌过期时间 (1小时)
            ticket.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1);
            _logger.LogDebug("为用户 {UserId} 设置认证票据过期时间: {ExpiryTime}",
                user.Id, ticket.Properties.ExpiresUtc);

            // 如果生成了刷新令牌，添加到响应头
            if (!string.IsNullOrEmpty(newRefreshToken) && newRefreshTokenExpiryTime.HasValue)
            {
                Response.Headers.Append("New-Refresh-Token", newRefreshToken);
                Response.Headers.Append("New-Refresh-Token-Expiry",
                    newRefreshTokenExpiryTime.Value.ToString("o")); // ISO 8601格式
            }

            _logger.LogInformation("成功完成用户 {UserId} 的认证票据创建", user.Id);

            // 签发令牌
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "为用户 {UserId} 创建认证票据时发生错误: {ErrorMessage}",
                user.Id, ex.Message);
            throw new AuthenticationException("server_error", "创建认证票据失败: " + ex.Message);
        }
    }

    #endregion

    #region 扩展私有方法

    /// <summary>
    /// 处理客户端凭据授权类型。
    /// </summary>
    /// <param name="request">OpenID Connect 请求。</param>
    /// <returns>包含访问令牌和其他相关信息的响应。</returns>
    /// <exception cref="AuthenticationException">如果客户端认证失败，则抛出异常。</exception>
    private async Task<IActionResult> HandleClientCredentialsGrantTypeAsync(OpenIddictRequest request)
    {
        _logger.LogInformation("Handling client credentials grant type for client: {ClientId}", request.ClientId);

        if (request.ClientId != null)
        {
            var client = await _applicationManager.FindByClientIdAsync(request.ClientId);
            if (client == null)
            {
                _logger.LogWarning("Client credentials authentication failed. Client not found: {ClientId}",
                    request.ClientId);
                throw new AuthenticationException("invalid_client", ("The client is not registered."));
            }

            if (request.ClientSecret != null &&
                !await _applicationManager.ValidateClientSecretAsync(client, request.ClientSecret))
            {
                _logger.LogWarning("Client credentials authentication failed. Invalid secret for client: {ClientId}",
                    request.ClientId);
                throw new AuthenticationException("invalid_client", ("Invalid client credentials."));
            }

            var identity = new ClaimsIdentity(
                authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.AddClaim(Claims.Subject, request.ClientId!)
                .SetDestinations(_ => [Destinations.AccessToken, Destinations.IdentityToken]);


            // 可以选择添加客户端的名称
            var displayName = await _applicationManager.GetDisplayNameAsync(client);
            if (!string.IsNullOrEmpty(displayName))
            {
                identity.AddClaim(Claims.Name, displayName)
                    .SetDestinations(_ => [Destinations.AccessToken, Destinations.IdentityToken]);
            }

            // 添加 scopes
            var scopes = request.GetScopes();
            if (!scopes.Any())
            {
                // 如果请求中没有 scope，则使用客户端的默认 scopes
                var clientScopes = await _applicationManager.GetPermissionsAsync(client);
                // 过滤掉 offline_access，客户端凭据不需要 refresh token
                scopes = clientScopes
                    .Where(p => !p.Equals(Permissions.GrantTypes.RefreshToken, StringComparison.OrdinalIgnoreCase))
                    .ToImmutableArray();
            }

            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(scopes);
            principal.SetResources(await _scopeManager.ListResourcesAsync(scopes).ToListAsync());

            _logger.LogInformation("Client credentials authentication successful for client: {ClientId}",
                request.ClientId);

            // Create and sign the tokens
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return await HandlePasswordGrantTypeAsync(request);
    }

    #endregion
}