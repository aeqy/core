using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Co.Identity.Services;

public class ClientConfigurationService(
    IOpenIddictApplicationManager applicationManager,
    ILogger<ClientConfigurationService> logger)
{
    public async Task SeedClientsAsync()
    {
        // 添加客户端应用
        if (await applicationManager.FindByClientIdAsync("web-client") == null)
        {
            logger.LogInformation("创建Web客户端应用");
            
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "web-client",
                ClientSecret = "web-client-secret",
                DisplayName = "Web应用客户端",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Revocation,
                    Permissions.Endpoints.Introspection,
                    
                    Permissions.GrantTypes.Password,
                    Permissions.GrantTypes.RefreshToken,
                    
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    
                    Permissions.Prefixes.Scope + "api"
                }
            });
        }

        // 添加SPA客户端
        if (await applicationManager.FindByClientIdAsync("spa-client") == null)
        {
            logger.LogInformation("创建SPA客户端应用");
            
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "spa-client",
                ClientSecret = "spa-client-secret",
                DisplayName = "SPA应用客户端",
                RedirectUris = { new Uri("https://spa.example.com/callback") },
                PostLogoutRedirectUris = { new Uri("https://spa.example.com") },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Logout,
                    
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    
                    Permissions.ResponseTypes.Code,
                    
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    
                    Permissions.Prefixes.Scope + "api"
                }
            });
        }

        // 添加移动客户端
        if (await applicationManager.FindByClientIdAsync("mobile-client") == null)
        {
            logger.LogInformation("创建移动客户端应用");
            
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "mobile-client",
                ClientSecret = "mobile-client-secret",
                DisplayName = "移动应用客户端",
                RedirectUris = { new Uri("co.mobile://callback") },
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Revocation,
                    
                    Permissions.GrantTypes.Password,
                    Permissions.GrantTypes.RefreshToken,
                    
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    
                    Permissions.Prefixes.Scope + "api"
                }
            });
        }

        // 添加服务间通信客户端
        if (await applicationManager.FindByClientIdAsync("service-client") == null)
        {
            logger.LogInformation("创建服务客户端应用");
            
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "service-client",
                ClientSecret = "service-client-secret",
                DisplayName = "服务间通信客户端",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    
                    Permissions.GrantTypes.ClientCredentials,
                    
                    Permissions.Prefixes.Scope + "api"
                }
            });
        }
    }
} 