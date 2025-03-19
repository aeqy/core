using System.Security.Cryptography.X509Certificates;
using Co.Infrastructure.Data;
using OpenIddict.Abstractions;

namespace Co.WebApi.Extensions;

/// <summary>
/// OpenIddict配置类
/// </summary>
public static class OpenIddictConfiguration
{
    /// <summary>
    /// 配置OpenIddict
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection ConfigureOpenIddict(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOpenIddict()
            // 注册 OpenIddict 核心组件
            .AddCore(options =>
            {
                // 配置 OpenIddict 使用 EF Core 作为存储引擎
                options.UseEntityFrameworkCore()
                    .UseDbContext<CoDbContext>()
                    .ReplaceDefaultEntities<Guid>();
            })
            // 注册 OpenIddict 服务器组件
            .AddServer(options =>
            {
                // 启用授权码、密码、客户端凭据和刷新令牌流
                options
                    .AllowAuthorizationCodeFlow()
                    .AllowPasswordFlow()
                    .AllowClientCredentialsFlow()
                    .AllowRefreshTokenFlow();

                // 配置 Token 端点
                options
                    .SetTokenEndpointUris("/connect/token")
                    .SetAuthorizationEndpointUris("/connect/authorize")
                    .SetIntrospectionEndpointUris("/connect/introspect")
                    .SetRevocationEndpointUris("/connect/revoke");

                // 注册 ASP.NET Core 主机并配置授权端点
                options.UseAspNetCore()
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough()
                    .DisableTransportSecurityRequirement();

                // 配置加密和签名凭证
                if (configuration.GetValue<bool>("OpenIddict:UseDevelopmentCertificates", true))
                {
                    // 开发环境使用开发证书
                    options.AddDevelopmentEncryptionCertificate()
                        .AddDevelopmentSigningCertificate();
                }
                else
                {
                    // 生产环境从配置中获取证书
                    var encryptionCertificate = GetCertificate(configuration["OpenIddict:EncryptionCertificate"]);
                    var signingCertificate = GetCertificate(configuration["OpenIddict:SigningCertificate"]);

                    if (encryptionCertificate != null)
                    {
                        options.AddEncryptionCertificate(encryptionCertificate);
                    }

                    if (signingCertificate != null)
                    {
                        options.AddSigningCertificate(signingCertificate);
                    }
                }

                // 注册作用域
                options.RegisterScopes(
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.Roles,
                    "api"
                );

                // 配置访问令牌的格式
                if (configuration.GetValue<bool>("OpenIddict:UseJwt", true))
                {
                    options.DisableAccessTokenEncryption();
                }
            })
            // 注册 OpenIddict 验证组件
            .AddValidation(options =>
            {
                // 导入本地服务器实例
                options.UseLocalServer();

                // 注册 ASP.NET Core 主机
                options.UseAspNetCore();
            });
        return services;
    }
    
    /// <summary>
    /// 从配置获取证书
    /// </summary>
    private static X509Certificate2? GetCertificate(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }
        
        try
        {
            return new X509Certificate2(path);
        }
        catch
        {
            return null;
        }
    }
    
}