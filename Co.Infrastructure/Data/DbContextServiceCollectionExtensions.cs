using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Co.Infrastructure.Data;

/// <summary>
/// 数据库上下文服务集合扩展
/// </summary>
public static class DbContextServiceCollectionExtensions
{
    /// <summary>
    /// 添加数据库服务
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection AddDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        // 配置 DbContext
        services.AddDbContext<CoDbContext>(options =>
        {
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"),
                npgsql =>
                {
                    // 配置迁移程序集
                    npgsql.MigrationsAssembly(typeof(CoDbContext).Assembly.GetName().Name);
                    // 启用重试机制
                    npgsql.EnableRetryOnFailure();
                });
            
            // 开发环境下启用详细错误信息和敏感数据记录
            if (configuration.GetValue<bool>("EnableDetailedDbLogging", false))
            {
                options.EnableDetailedErrors();
                options.EnableSensitiveDataLogging();
            }
        });

        // 配置 Identity
        ConfigureIdentity(services, configuration);

        // 配置 OpenIddict
        ConfigureOpenIddict(services, configuration);

        // 添加种子数据服务
        services.AddScoped<SeedDataService>();

        return services;
    }
    
    /// <summary>
    /// 配置 Identity
    /// </summary>
    private static void ConfigureIdentity(IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentity<IdentityUser<Guid>, IdentityRole<Guid>>(options =>
            {
                // 密码设置
                options.Password.RequiredLength = configuration.GetValue<int>("IdentityOptions:Password:RequiredLength", 6);
                options.Password.RequireDigit = configuration.GetValue<bool>("IdentityOptions:Password:RequireDigit", true);
                options.Password.RequireLowercase = configuration.GetValue<bool>("IdentityOptions:Password:RequireLowercase", true);
                options.Password.RequireUppercase = configuration.GetValue<bool>("IdentityOptions:Password:RequireUppercase", true);
                options.Password.RequireNonAlphanumeric = configuration.GetValue<bool>("IdentityOptions:Password:RequireNonAlphanumeric", true);

                // 用户设置
                options.User.RequireUniqueEmail = configuration.GetValue<bool>("IdentityOptions:User:RequireUniqueEmail", true);
                options.User.AllowedUserNameCharacters = configuration.GetValue<string>(
                    "IdentityOptions:User:AllowedUserNameCharacters", 
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+");

                // 登录设置
                options.SignIn.RequireConfirmedEmail = configuration.GetValue<bool>("IdentityOptions:SignIn:RequireConfirmedEmail", true);
                options.SignIn.RequireConfirmedAccount = configuration.GetValue<bool>("IdentityOptions:SignIn:RequireConfirmedAccount", true);

                // 锁定设置
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(
                    configuration.GetValue<int>("IdentityOptions:Lockout:DefaultLockoutTimeSpanInMinutes", 5));
                options.Lockout.MaxFailedAccessAttempts = configuration.GetValue<int>("IdentityOptions:Lockout:MaxFailedAccessAttempts", 5);
                options.Lockout.AllowedForNewUsers = configuration.GetValue<bool>("IdentityOptions:Lockout:AllowedForNewUsers", true);
            })
            .AddEntityFrameworkStores<CoDbContext>()
            .AddDefaultTokenProviders();
    }
    
    /// <summary>
    /// 配置 OpenIddict
    /// </summary>
    private static void ConfigureOpenIddict(IServiceCollection services, IConfiguration configuration)
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
