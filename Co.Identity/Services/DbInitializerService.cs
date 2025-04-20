using Co.Identity.Models;
using Microsoft.AspNetCore.Identity;

namespace Co.Identity.Services;

/// <summary>
/// 数据库初始化服务
/// </summary>
public class DbInitializerService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly ILogger<DbInitializerService> _logger;
    private readonly IConfiguration _configuration;

    /// <summary>
    /// 构造函数
    /// </summary>
    public DbInitializerService(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        ILogger<DbInitializerService> logger,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
        _configuration = configuration;
    }

    /// <summary>
    /// 初始化数据库
    /// </summary>
    public async Task InitializeAsync()
    {
        try
        {
            // 创建角色
            await EnsureRolesCreatedAsync();
            
            // 创建管理员用户
            await EnsureAdminUserCreatedAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "数据库初始化失败");
            throw;
        }
    }

    /// <summary>
    /// 确保角色已创建
    /// </summary>
    private async Task EnsureRolesCreatedAsync()
    {
        _logger.LogInformation("正在创建角色...");
        
        string[] roleNames = { "Admin", "User" };
        
        foreach (var roleName in roleNames)
        {
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                _logger.LogInformation("创建角色 {RoleName}", roleName);
                
                var description = roleName == "Admin" ? "管理员角色" : "普通用户角色";
                await _roleManager.CreateAsync(new ApplicationRole 
                { 
                    Name = roleName, 
                    Description = description 
                });
            }
        }
    }

    /// <summary>
    /// 确保管理员用户已创建
    /// </summary>
    private async Task EnsureAdminUserCreatedAsync()
    {
        _logger.LogInformation("正在创建管理员用户...");
        
        var adminEmail = _configuration["AdminUser:Email"] ?? "admin@example.com";
        var adminPassword = _configuration["AdminUser:Password"] ?? "Admin123!";
        
        var adminUser = await _userManager.FindByEmailAsync(adminEmail);
        
        if (adminUser == null)
        {
            _logger.LogInformation("创建管理员用户 {Email}", adminEmail);
            
            adminUser = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                FirstName = "System",
                LastName = "Administrator",
                EmailConfirmed = true,
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };
            
            var result = await _userManager.CreateAsync(adminUser, adminPassword);
            
            if (result.Succeeded)
            {
                _logger.LogInformation("管理员用户创建成功");
                await _userManager.AddToRoleAsync(adminUser, "Admin");
            }
            else
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("创建管理员用户失败: {Errors}", errors);
                throw new Exception($"创建管理员用户失败: {errors}");
            }
        }
        else
        {
            _logger.LogInformation("管理员用户已存在");
            
            // 确保用户在Admin角色中
            if (!await _userManager.IsInRoleAsync(adminUser, "Admin"))
            {
                await _userManager.AddToRoleAsync(adminUser, "Admin");
            }
        }
    }
} 