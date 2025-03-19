using Co.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;

namespace Co.WebApi.Extensions;

/// <summary>
/// Identity服务扩展类
/// </summary>
public static class IdentityServicesExtensions
{
    /// <summary>
    /// 添加Identity服务
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection AddIdentityServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentity<IdentityUser<Guid>, IdentityRole<Guid>>(options =>
            {
                // 密码设置
                options.Password.RequiredLength =
                    configuration.GetValue<int>("IdentityOptions:Password:RequiredLength", 6);
                options.Password.RequireDigit =
                    configuration.GetValue<bool>("IdentityOptions:Password:RequireDigit", true);
                options.Password.RequireLowercase =
                    configuration.GetValue<bool>("IdentityOptions:Password:RequireLowercase", true);
                options.Password.RequireUppercase =
                    configuration.GetValue<bool>("IdentityOptions:Password:RequireUppercase", true);
                options.Password.RequireNonAlphanumeric =
                    configuration.GetValue<bool>("IdentityOptions:Password:RequireNonAlphanumeric", true);

                // 用户设置
                options.User.RequireUniqueEmail =
                    configuration.GetValue<bool>("IdentityOptions:User:RequireUniqueEmail", true);
                options.User.AllowedUserNameCharacters = configuration.GetValue<string>(
                    "IdentityOptions:User:AllowedUserNameCharacters",
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+");

                // 登录设置
                options.SignIn.RequireConfirmedEmail =
                    configuration.GetValue<bool>("IdentityOptions:SignIn:RequireConfirmedEmail", true);
                options.SignIn.RequireConfirmedAccount =
                    configuration.GetValue<bool>("IdentityOptions:SignIn:RequireConfirmedAccount", true);

                // 锁定设置
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(
                    configuration.GetValue<int>("IdentityOptions:Lockout:DefaultLockoutTimeSpanInMinutes", 5));
                options.Lockout.MaxFailedAccessAttempts =
                    configuration.GetValue<int>("IdentityOptions:Lockout:MaxFailedAccessAttempts", 5);
                options.Lockout.AllowedForNewUsers =
                    configuration.GetValue<bool>("IdentityOptions:Lockout:AllowedForNewUsers", true);
            })
            .AddEntityFrameworkStores<CoDbContext>()
            .AddDefaultTokenProviders();
        
        return services;
    }
}