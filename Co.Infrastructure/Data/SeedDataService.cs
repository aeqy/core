using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace Co.Infrastructure.Data;

/// <summary>
/// 种子数据服务
/// </summary>
public class SeedDataService
{
    private readonly CoDbContext _context;
    private readonly UserManager<IdentityUser<Guid>> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly IConfiguration _configuration;
    private readonly ILogger<SeedDataService> _logger;

    /// <summary>
    /// 构造函数
    /// </summary>
    public SeedDataService(
        CoDbContext context,
        UserManager<IdentityUser<Guid>> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        IConfiguration configuration,
        ILogger<SeedDataService> logger)
    {
        _context = context;
        _userManager = userManager;
        _roleManager = roleManager;
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// 初始化种子数据
    /// </summary>
    public async Task SeedAsync()
    {
        try
        {
            // 应用数据库迁移
            await _context.Database.MigrateAsync();

            // 初始化角色
            if (_configuration.GetValue<bool>("SeedData:SeedRoles", true))
            {
                await SeedRolesAsync();
            }

            // 初始化用户
            if (_configuration.GetValue<bool>("SeedData:SeedUsers", true))
            {
                await SeedUsersAsync();
            }

            // 初始化 OpenIddict 数据
            if (_configuration.GetValue<bool>("SeedData:SeedOpenIddict", true))
            {
                await SeedOpenIddictScopesAsync();
                await SeedOpenIddictApplicationsAsync();
            }

            _logger.LogInformation("所有种子数据初始化完成");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "初始化种子数据时发生错误");
            throw;
        }
    }

    /// <summary>
    /// 初始化角色
    /// </summary>
    private async Task SeedRolesAsync()
    {
        // 默认角色列表
        string[] roles = { "SuperAdmin", "Admin", "User", "Manager" };

        foreach (var role in roles)
        {
            if (!await _roleManager.RoleExistsAsync(role))
            {
                _logger.LogInformation("创建角色: {Role}", role);

                var identityRole = new IdentityRole<Guid>(role);
                var result = await _roleManager.CreateAsync(identityRole);

                if (!result.Succeeded)
                {
                    _logger.LogError("创建角色 '{Role}' 失败: {Errors}", role,
                        string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
        }
    }

    /// <summary>
    /// 初始化用户
    /// </summary>
    private async Task SeedUsersAsync()
    {
        // 创建超级管理员
        await CreateUserIfNotExistsAsync(
            "superadmin",
            "superadmin@example.com",
            _configuration["SeedData:SuperAdminPassword"] ?? "SuperAdmin@123",
            new[] { "SuperAdmin" }
        );
        
        // 创建管理员
        await CreateUserIfNotExistsAsync(
            "admin",
            "admin@example.com",
            _configuration["SeedData:AdminPassword"] ?? "Admin@123",
            new[] { "Admin" }
        );

        // 创建普通用户
        await CreateUserIfNotExistsAsync(
            "user",
            "user@example.com",
            _configuration["SeedData:UserPassword"] ?? "User@123",
            new[] { "User" }
        );

        // 创建经理用户
        await CreateUserIfNotExistsAsync(
            "manager",
            "manager@example.com",
            _configuration["SeedData:ManagerPassword"] ?? "Manager@123",
            new[] { "Manager" }
        );
        
        // 创建测试用户（拥有所有角色）
        await CreateUserIfNotExistsAsync(
            "test",
            "test@example.com",
            _configuration["SeedData:TestUserPassword"] ?? "Test@123",
            new[] { "SuperAdmin", "Admin", "User", "Manager" }
        );
    }

    /// <summary>
    /// 如果用户不存在则创建
    /// </summary>
    private async Task CreateUserIfNotExistsAsync(
        string userName,
        string email,
        string password,
        string[] roles)
    {
        var user = await _userManager.FindByNameAsync(userName);

        if (user == null)
        {
            _logger.LogInformation("创建用户: {UserName}", userName);

            user = new IdentityUser<Guid>
            {
                UserName = userName,
                Email = email,
                EmailConfirmed = true
            };

            _logger.LogInformation("尝试创建用户 '{UserName}'，密码：{Password}", userName, password);
            var passwordOptions = $"RequireDigit={_userManager.Options.Password.RequireDigit}, " +
                                $"RequireLowercase={_userManager.Options.Password.RequireLowercase}, " +
                                $"RequireUppercase={_userManager.Options.Password.RequireUppercase}, " +
                                $"RequireNonAlphanumeric={_userManager.Options.Password.RequireNonAlphanumeric}, " +
                                $"RequiredLength={_userManager.Options.Password.RequiredLength}";
            _logger.LogInformation("密码策略：{PasswordOptions}", passwordOptions);
            
            var result = await _userManager.CreateAsync(user, password);

            if (result.Succeeded)
            {
                _logger.LogInformation("为用户 '{UserName}' 添加角色: {Roles}", userName, string.Join(", ", roles));

                foreach (var role in roles)
                {
                    result = await _userManager.AddToRoleAsync(user, role);

                    if (!result.Succeeded)
                    {
                        _logger.LogError("将角色 '{Role}' 添加到用户 '{UserName}' 失败: {Errors}",
                            role, userName, string.Join(", ", result.Errors.Select(e => e.Description)));
                    }
                }
            }
            else
            {
                _logger.LogError("创建用户 '{UserName}' 失败: {Errors}",
                    userName, string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
        else
        {
            _logger.LogInformation("用户 '{UserName}' 已存在，跳过创建", userName);
        }
    }

    /// <summary>
    /// 初始化 OpenIddict 作用域
    /// </summary>
    private async Task SeedOpenIddictScopesAsync()
    {
        // 创建 API 作用域
        await CreateScopeIfNotExistsAsync("api", "API 访问权限", new[]
        {
            OpenIddictConstants.Permissions.Scopes.Profile,
            OpenIddictConstants.Permissions.Scopes.Email,
            OpenIddictConstants.Permissions.Scopes.Roles
        });

        // 创建离线访问作用域
        await CreateScopeIfNotExistsAsync("offline_access", "离线访问权限");
    }

    /// <summary>
    /// 如果作用域不存在则创建
    /// </summary>
    private async Task CreateScopeIfNotExistsAsync(string name, string displayName, string[]? resources = null)
    {
        if (await _scopeManager.FindByNameAsync(name) == null)
        {
            _logger.LogInformation("创建作用域: {ScopeName}", name);

            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = name,
                DisplayName = displayName
            };

            if (resources != null)
            {
                foreach (var resource in resources)
                {
                    descriptor.Resources.Add(resource);
                }
            }

            await _scopeManager.CreateAsync(descriptor);
        }
    }

    /// <summary>
    /// 初始化 OpenIddict 应用程序
    /// </summary>
    private async Task SeedOpenIddictApplicationsAsync()
    {
        // 创建 SPA 客户端应用程序
        await CreateApplicationIfNotExistsAsync(
            "spa-client",
            "SPA 客户端应用程序",
            null, // SPA 客户端是公共客户端，不需要客户端密钥
            OpenIddictConstants.ClientTypes.Public,
            new[]
            {
                OpenIddictConstants.GrantTypes.AuthorizationCode,
                OpenIddictConstants.GrantTypes.RefreshToken
            },
            new[] { "https://localhost:5001/callback", "https://localhost:5001/silent-refresh.html" },
            new[] { "api", "offline_access" }
        );

        // 创建服务客户端应用程序
        await CreateApplicationIfNotExistsAsync(
            "service-client",
            "服务客户端应用程序",
            _configuration["SeedData:OpenIddict:ServiceClientSecret"] ?? "service-client-secret",
            OpenIddictConstants.ClientTypes.Confidential,
            new[]
            {
                OpenIddictConstants.GrantTypes.ClientCredentials
            },
            Array.Empty<string>(),
            new[] { "api" }
        );

        // 创建密码客户端应用程序
        await CreateApplicationIfNotExistsAsync(
            "password-client",
            "密码客户端应用程序",
            _configuration["SeedData:OpenIddict:PasswordClientSecret"] ?? "password-client-secret",
            OpenIddictConstants.ClientTypes.Confidential,
            new[]
            {
                OpenIddictConstants.GrantTypes.Password,
                OpenIddictConstants.GrantTypes.RefreshToken
            },
            Array.Empty<string>(),
            new[] { "api", "offline_access" }
        );
    }

    /// <summary>
    /// 如果应用程序不存在则创建
    /// </summary>
    private async Task CreateApplicationIfNotExistsAsync(
        string clientId,
        string displayName,
        string? clientSecret,
        string clientType,
        string[] grantTypes,
        string[] redirectUris,
        string[] scopes)
    {
        if (await _applicationManager.FindByClientIdAsync(clientId) == null)
        {
            _logger.LogInformation("创建 OpenIddict 客户端: {ClientId}", clientId);

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                DisplayName = displayName,
                ClientType = clientType
            };

            // 配置授权类型
            foreach (var grantType in grantTypes)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.GrantType + grantType);
            }

            // 配置重定向 URI
            foreach (var uri in redirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(uri));
            }

            // 配置令牌端点
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

            // 如果使用授权码流，则需要授权端点
            if (grantTypes.Contains(OpenIddictConstants.GrantTypes.AuthorizationCode))
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
            }

            // 如果有重定向 URI，则启用撤销端点
            if (redirectUris.Any())
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);
            }

            // 配置作用域
            foreach (var scope in scopes)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
            }

            await _applicationManager.CreateAsync(descriptor);
        }
        else
        {
            _logger.LogInformation("OpenIddict 客户端 '{ClientId}' 已存在，跳过创建", clientId);
        }
    }
} 