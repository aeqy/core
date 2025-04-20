using System.Security.Claims;
using Co.Identity.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Co.Identity.Controllers;

public class AuthorizeController(
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictAuthorizationManager authorizationManager,
    IOpenIddictScopeManager scopeManager,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    ILogger<AuthorizeController> logger)
    : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;

    [HttpGet("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // 检查用户是否已经登录
        if (!User.Identity.IsAuthenticated)
        {
            // 如果未登录，重定向到登录页面
            var properties = new Microsoft.AspNetCore.Authentication.AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                    Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
            };

            return Challenge(properties);
        }

        // 获取当前用户
        var user = await userManager.GetUserAsync(User) ??
            throw new InvalidOperationException("当前用户信息无法检索。");

        // 获取当前请求的客户端应用信息
        var application = await applicationManager.FindByClientIdAsync(request.ClientId) ??
            throw new InvalidOperationException("无法找到请求的客户端应用。");

        // 获取客户端应用的显示名称
        var applicationName = await applicationManager.GetDisplayNameAsync(application) ?? 
            request.ClientId;

        // 检索请求的作用域
        var scopes = request.GetScopes();
        
        // 准备作用域信息，用于在用户界面中显示
        var scopeDetails = new List<ScopeViewModel>();
        
        foreach (var scope in scopes)
        {
            var scopeDescription = scope switch
            {
                Scopes.Email => "访问您的电子邮件地址",
                Scopes.Profile => "访问您的基本个人信息",
                Scopes.Roles => "访问您的角色信息",
                "api" => "访问API资源",
                "openid" => "用于识别您的身份",
                _ => $"访问 {scope}"
            };
            
            scopeDetails.Add(new ScopeViewModel
            {
                Name = scope,
                Description = scopeDescription
            });
        }

        // 检查用户是否已经授权过这个应用和这些作用域
        var authorizations = await authorizationManager.FindAsync(
            subject: await userManager.GetUserIdAsync(user),
            client: await applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: scopes).ToListAsync();

        // 如果用户已经授权过所有请求的作用域，则自动授权
        if (authorizations.Count != 0 && authorizations.All(authorization => 
            {
                var authScopes = authorizationManager.GetScopesAsync(authorization).Result.ToList();
                return scopes.All(scope => authScopes.Contains(scope));
            }))
        {
            logger.LogInformation("用户已授权过此应用程序和请求的作用域，自动授权");
            
            // 创建身份认证票据
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
            identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
            identity.SetDestinations(GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // 显示授权视图，让用户确认或拒绝授权
        return View("Authorize", new AuthorizeViewModel
        {
            ApplicationName = applicationName,
            Scopes = scopeDetails,
            RequestId = request.RequestId
        });
    }

    [Authorize, HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Accept()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // 获取当前用户
        var user = await userManager.GetUserAsync(User) ??
            throw new InvalidOperationException("当前用户信息无法检索。");

        // 获取客户端应用信息
        var application = await applicationManager.FindByClientIdAsync(request.ClientId) ??
            throw new InvalidOperationException("无法找到请求的客户端应用。");

        // 创建身份认证票据
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
        identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
        identity.SetDestinations(GetDestinations);

        // 创建永久授权记录，以便将来自动授权
        var authorization = await authorizationManager.CreateAsync(
            principal: new ClaimsPrincipal(identity),
            subject: await userManager.GetUserIdAsync(user),
            client: await applicationManager.GetIdAsync(application),
            type: AuthorizationTypes.Permanent,
            scopes: identity.GetScopes());

        logger.LogInformation("用户同意授权应用程序 {ClientId} 访问作用域 {Scopes}", 
            request.ClientId, string.Join(", ", request.GetScopes()));

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [Authorize, HttpPost("~/connect/authorize/deny"), ValidateAntiForgeryToken]
    public IActionResult Deny()
    {
        logger.LogInformation("用户拒绝授权请求");
    
        var properties = new Microsoft.AspNetCore.Authentication.AuthenticationProperties(
            new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "用户拒绝了授权请求"
            });
    
        return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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