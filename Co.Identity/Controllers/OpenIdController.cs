using System.Collections.Immutable;
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

    [HttpGet("~/connect/authorize")]
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
            // 处理令牌撤销
            return Ok();
        }

        return Ok();
    }

    [HttpPost("~/connect/introspect")]
    public async Task<IActionResult> Introspect()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // 查询令牌状态
        if (!string.IsNullOrEmpty(request.Token))
        {
            // 处理令牌查询
            return Ok();
        }

        return BadRequest(new OpenIddictResponse
        {
            Error = OpenIddictConstants.Errors.InvalidRequest,
            ErrorDescription = "令牌无效"
        });
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