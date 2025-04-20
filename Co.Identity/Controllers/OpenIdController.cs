using System.Security.Claims;
using Co.Identity.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Co.Identity.Services;

namespace Co.Identity.Controllers;

public class OpenIdController(
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager,
    IOpenIddictApplicationManager applicationManager,
    ILogger<OpenIdController> logger)
    : Controller
{
    private readonly ILogger<OpenIdController> _logger = logger;

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Token()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        if (request == null)
        {
            return BadRequest(new { error = "invalid_request" });
        }

        if (request.IsPasswordGrantType())
        {
            // 处理密码授权模式
            var user = await userManager.FindByNameAsync(request.Username);
            if (user == null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "用户名或密码不正确"
                    }));
            }

            // 验证密码
            var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            if (!result.Succeeded)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "用户名或密码不正确"
                    }));
            }

            // 创建ClaimsIdentity
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // 添加标准声明
            identity.AddClaim(Claims.Subject, await userManager.GetUserIdAsync(user));
            identity.AddClaim(Claims.Name, await userManager.GetUserNameAsync(user));
            identity.AddClaim(Claims.Email, await userManager.GetEmailAsync(user));

            // 添加自定义声明
            if (!string.IsNullOrEmpty(user.FirstName))
                identity.AddClaim("given_name", user.FirstName);
                
            if (!string.IsNullOrEmpty(user.LastName))
                identity.AddClaim("family_name", user.LastName);

            // 添加用户角色
            foreach (var role in await userManager.GetRolesAsync(user))
            {
                identity.AddClaim(Claims.Role, role);
            }

            // 设置资源
            var resources = new List<string>();
            identity.SetScopes(request.GetScopes());
            identity.SetDestinations(GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        else if (request.IsRefreshTokenGrantType())
        {
            // 处理刷新令牌授权模式
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var userId = result.Principal?.GetClaim(Claims.Subject);
            
            if (string.IsNullOrEmpty(userId))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "刷新令牌无效"
                    }));
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "用户不存在"
                    }));
            }

            // 创建新的ClaimsIdentity
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // 添加标准声明
            identity.AddClaim(Claims.Subject, await userManager.GetUserIdAsync(user));
            identity.AddClaim(Claims.Name, await userManager.GetUserNameAsync(user));
            identity.AddClaim(Claims.Email, await userManager.GetEmailAsync(user));

            // 添加自定义声明
            if (!string.IsNullOrEmpty(user.FirstName))
                identity.AddClaim("given_name", user.FirstName);
                
            if (!string.IsNullOrEmpty(user.LastName))
                identity.AddClaim("family_name", user.LastName);

            // 添加用户角色
            foreach (var role in await userManager.GetRolesAsync(user))
            {
                identity.AddClaim(Claims.Role, role);
            }

            // 设置作用域和目标
            identity.SetScopes(request.GetScopes());
            identity.SetDestinations(GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        else if (request.IsClientCredentialsGrantType())
        {
            // 处理客户端凭证授权模式
            var application = await applicationManager.FindByClientIdAsync(request.ClientId);
            if (application == null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "客户端不存在"
                    }));
            }

            // 创建应用程序身份
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // 添加应用程序声明
            identity.AddClaim(Claims.Subject, await applicationManager.GetClientIdAsync(application));
            identity.AddClaim(Claims.Name, await applicationManager.GetDisplayNameAsync(application) ?? "Unknown");

            // 设置作用域和目标
            identity.SetScopes(request.GetScopes());
            identity.SetDestinations(GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnsupportedGrantType,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "不支持的授权类型"
            }));
    }

    [HttpGet("~/connect/authorize2")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        if (request == null)
        {
            return BadRequest(new { error = "invalid_request" });
        }

        // 如果用户尚未登录，重定向到登录页面
        if (!User.Identity.IsAuthenticated)
        {
            // 存储当前请求以便登录后重定向回来
            var properties = new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                    Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
            };

            return Challenge(properties);
        }

        // 查找当前用户
        var user = await userManager.GetUserAsync(User);
        if (user == null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "用户不存在"
                }));
        }

        // 创建ClaimsIdentity
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // 添加标准声明
        identity.AddClaim(Claims.Subject, await userManager.GetUserIdAsync(user));
        identity.AddClaim(Claims.Name, await userManager.GetUserNameAsync(user));
        identity.AddClaim(Claims.Email, await userManager.GetEmailAsync(user));

        // 添加自定义声明
        if (!string.IsNullOrEmpty(user.FirstName))
            identity.AddClaim("given_name", user.FirstName);
            
        if (!string.IsNullOrEmpty(user.LastName))
            identity.AddClaim("family_name", user.LastName);

        // 添加用户角色
        foreach (var role in await userManager.GetRolesAsync(user))
        {
            identity.AddClaim(Claims.Role, role);
        }

        // 设置作用域和目标
        identity.SetScopes(request.GetScopes());
        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/revoke")]
    public async Task<IActionResult> Revoke()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // 撤销令牌
        if (!string.IsNullOrEmpty(request.Token))
        {
            var tokenManager = HttpContext.RequestServices.GetRequiredService<IOpenIddictTokenManager>();
            var tokenCacheService = HttpContext.RequestServices.GetRequiredService<ITokenCacheService>();
            
            // 尝试找到令牌
            var token = await tokenManager.FindByReferenceIdAsync(request.Token);
            
            if (token != null)
            {
                // 获取令牌类型
                var tokenType = await tokenManager.GetTypeAsync(token);
                var tokenSubject = await tokenManager.GetSubjectAsync(token);
                
                // 根据令牌类型采取相应的操作
                if (tokenType == TokenTypeHints.AccessToken)
                {
                    // 撤销访问令牌
                    await tokenManager.TryRevokeAsync(token);
                    await tokenCacheService.RevokeTokenAsync(request.Token, TimeSpan.FromHours(1));
                    _logger.LogInformation("访问令牌已撤销: {TokenId}", request.Token);
                }
                else if (tokenType == TokenTypeHints.RefreshToken)
                {
                    // 撤销刷新令牌，同时查找并撤销关联的访问令牌
                    await tokenManager.TryRevokeAsync(token);
                    
                    // 尝试从缓存中获取关联的访问令牌
                    var accessToken = await tokenCacheService.GetAccessTokenAsync(request.Token);
                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        // 撤销关联的访问令牌
                        await tokenCacheService.RevokeTokenAsync(accessToken, TimeSpan.FromHours(1));
                        _logger.LogInformation("通过刷新令牌撤销了关联的访问令牌");
                    }
                    
                    // 如果在数据库中找到用户，清除其刷新令牌
                    if (!string.IsNullOrEmpty(tokenSubject))
                    {
                        var user = await userManager.FindByIdAsync(tokenSubject);
                        if (user != null && user.RefreshToken == request.Token)
                        {
                            user.RefreshToken = null;
                            user.RefreshTokenExpiryTime = null;
                            await userManager.UpdateAsync(user);
                        }
                    }
                    
                    _logger.LogInformation("刷新令牌已撤销: {TokenId}", request.Token);
                }
            }
            else
            {
                // 如果令牌不在OpenIddict存储中，仍将其标记为已撤销
                await tokenCacheService.RevokeTokenAsync(request.Token, TimeSpan.FromHours(1));
                _logger.LogInformation("令牌已添加到撤销列表: {TokenId}", request.Token);
            }
        }

        return Ok();
    }

    [HttpPost("~/connect/introspect")]
    public async Task<IActionResult> Introspect()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // 验证请求是否包含令牌
        if (string.IsNullOrEmpty(request.Token))
        {
            return BadRequest(new OpenIddictResponse
            {
                Error = Errors.InvalidRequest,
                ErrorDescription = "令牌参数缺失"
            });
        }

        // 获取必要的服务
        var tokenManager = HttpContext.RequestServices.GetRequiredService<IOpenIddictTokenManager>();
        var authorizationManager = HttpContext.RequestServices.GetRequiredService<IOpenIddictAuthorizationManager>();
        var tokenCacheService = HttpContext.RequestServices.GetRequiredService<ITokenCacheService>();

        // 准备响应
        var response = new OpenIddictResponse();
        
        // 设置默认为无效（返回IsActive=false）
        response.SetParameter("active", false);

        // 检查令牌是否被撤销
        if (await tokenCacheService.IsTokenRevokedAsync(request.Token))
        {
            return Ok(response);
        }

        // 尝试从OpenIddict存储中找到令牌
        var token = await tokenManager.FindByReferenceIdAsync(request.Token);
        if (token == null)
        {
            // 如果是JWT令牌，尝试验证其签名
            var tokenHandler = new JwtSecurityTokenHandler();
            if (tokenHandler.CanReadToken(request.Token))
            {
                try
                {
                    var key = Encoding.UTF8.GetBytes(HttpContext.RequestServices
                        .GetRequiredService<IConfiguration>()["JWT:Secret"] ?? 
                        throw new InvalidOperationException("JWT密钥未配置"));
                        
                    tokenHandler.ValidateToken(request.Token, new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = true,
                        ValidIssuer = HttpContext.RequestServices.GetRequiredService<IConfiguration>()["JWT:ValidIssuer"],
                        ValidateAudience = true,
                        ValidAudience = HttpContext.RequestServices.GetRequiredService<IConfiguration>()["JWT:ValidAudience"],
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero
                    }, out var validatedToken);

                    var jwtToken = (JwtSecurityToken)validatedToken;
                    
                    // 令牌有效，填充响应
                    response.SetParameter("active", true);
                    response.SetParameter("sub", jwtToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value);
                    response.SetParameter("client_id", jwtToken.Claims.FirstOrDefault(c => c.Type == "aud")?.Value);
                    response.SetParameter("iat", (long)(jwtToken.ValidFrom - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);
                    response.SetParameter("exp", (long)(jwtToken.ValidTo - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);
                    response.SetParameter("iss", jwtToken.Issuer);
                    response.SetParameter("token_type", TokenTypeHints.AccessToken);
                    
                    // 提取作用域
                    var scopeClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "scope");
                    if (scopeClaim != null)
                    {
                        response.SetParameter("scope", scopeClaim.Value);
                    }
                    
                    // 提取声明
                    if (jwtToken.Claims.Any(c => !new[] { "iss", "aud", "exp", "nbf", "iat", "jti", "scope" }.Contains(c.Type)))
                    {
                        // 对于每个不在排除列表中的声明，单独设置
                        foreach (var claim in jwtToken.Claims)
                        {
                            if (!new[] { "iss", "aud", "exp", "nbf", "iat", "jti", "scope" }.Contains(claim.Type))
                            {
                                // 使用单独的键值对形式设置每个声明
                                response.SetParameter(claim.Type, claim.Value);
                            }
                        }
                    }
                }
                catch
                {
                    // 令牌验证失败，保持Active=false
                }
            }
            
            return Ok(response);
        }

        // 如果令牌存在于存储中
        var authorization = await tokenManager.GetAuthorizationIdAsync(token) != null ?
            await authorizationManager.FindByIdAsync(await tokenManager.GetAuthorizationIdAsync(token)) : null;
            
        // 检查令牌类型和状态
        var tokenType = await tokenManager.GetTypeAsync(token);
        var tokenStatus = await tokenManager.GetStatusAsync(token);
        
        if (tokenStatus != Statuses.Valid)
        {
            return Ok(response); // 令牌状态无效
        }

        // 设置令牌有效
        response.SetParameter("active", true);
        
        // 填充基本信息
        response.SetParameter("sub", await tokenManager.GetSubjectAsync(token));
        response.SetParameter("client_id", await tokenManager.GetIdAsync(token));
        
        // 获取创建时间和过期时间
        var creationDate = await tokenManager.GetCreationDateAsync(token);
        var expirationDate = await tokenManager.GetExpirationDateAsync(token);
        
        if (creationDate.HasValue)
            response.SetParameter("iat", (long)(creationDate.Value - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);
            
        if (expirationDate.HasValue)
            response.SetParameter("exp", (long)(expirationDate.Value - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);
        
        response.SetParameter("token_type", tokenType);
        
        // 填充作用域信息
        if (authorization != null)
        {
            var scopes = await authorizationManager.GetScopesAsync(authorization);
            if (scopes.Any())
            {
                response.SetParameter("scope", string.Join(" ", scopes));
            }
        }
        
        return Ok(response);
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // 基于声明类型设置目标
        switch (claim.Type)
        {
            case Claims.Name:
                yield return Destinations.AccessToken;
                
                if (claim.Subject.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;
                
                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;
                
                if (claim.Subject.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;
                
                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;
                
                if (claim.Subject.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;
                
                yield break;

            case "given_name":
            case "family_name":
                yield return Destinations.AccessToken;
                
                if (claim.Subject.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;
                
                yield break;

            // 对于其他声明类型
            case Claims.Subject:
            default:
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                yield break;
        }
    }
} 