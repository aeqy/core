using Co.Infrastructure.Data;
using Co.WebApi.Filters;
using Co.WebApi.Middlewares;
using Microsoft.EntityFrameworkCore;

namespace Co.WebApi.Extensions;

internal static class ConfigureServicesExtensions
{
    public static void ConfigureServices(this IServiceCollection services, IConfiguration configuration)
    {
        // 添加控制器和API功能
        services.AddControllers(options =>
        {
            options.Filters.Add(typeof(ApiResponseFilterAttribute));
        });

        // 添加数据库服务
        services.AddDatabase(configuration);

        // 添加Identity和认证服务
        services.AddIdentityServices(configuration);

        // 添加OpenIddict服务
        services.ConfigureOpenIddict(configuration);

        // 添加API服务
        services.AddApiServices(configuration);

        // 添加授权策略
        services.AddAuthorization(options =>
        {
            // 需要Admin或SuperAdmin角色
            options.AddPolicy("RequireAdminRole", policy =>
                policy.RequireRole("Admin", "SuperAdmin"));

            // 仅需要SuperAdmin角色
            options.AddPolicy("RequireSuperAdminRole", policy =>
                policy.RequireRole("SuperAdmin"));
        });

        // 添加混合缓存服务
        services.AddHybridCache(configuration);

        // 添加种子数据服务
        services.AddScoped<SeedDataService>();

        // 添加日志服务
        services.AddLogging(logging => logging.AddConsole()); // 建议替换为 Serilog 或 NLog

        // 添加Swagger文档
        services.AddSwaggerDocumentation();
        // 添加CORS服务
        services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", builder =>
            {
                builder.AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader();
            });
        });
    }

    public static Task Configure(this WebApplication app)
    {
        // 开发环境配置
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        // 配置CORS
        app.UseCors("AllowAll");

        // 配置Swagger
        app.UseSwaggerDocumentation();
        
        // 在 app.UseRouting() 之前添加自定义中间件
        app.UseMiddleware<CorrelationIdMiddleware>();       // 必须放在最前面，确保所有请求都有 Correlation ID
        app.UseMiddleware<RequestResponseTimingMiddleware>();
        app.UseMiddleware<RequestLoggingMiddleware>();       // 通常放在异常处理之后
        app.UseMiddleware<GlobalExceptionHandlingMiddleware>();// 应该放在 UseRouting 之前, 捕获所有异常


        // 配置静态文件和路由
        app.UseDefaultFiles(); // Use Default Files
        app.UseStaticFiles(); // Use Static Files
        app.UseRouting(); // Use Routing

        // 配置认证和授权
        app.UseAuthentication(); // Use Authentication
        app.UseAuthorization(); // Use Authorization

        // 添加OpenIddict服务器中间件
        // app.UseOpenIddictServer();

        // 映射端点
        app.MapControllers(); // Map Controllers

        // 配置HTTPS
        app.UseHttpsRedirection(); // Use Https Redirection
        return Task.CompletedTask;
    }


    // 异步初始化数据库的方法
    public static async Task InitializeDatabaseAsync(WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var services = scope.ServiceProvider;
        try
        {
            // 获取并应用数据库迁移
            var context = services.GetRequiredService<CoDbContext>();
            context.Database.Migrate();

            // 初始化数据
            var seedDataService = services.GetRequiredService<SeedDataService>();
            await seedDataService.SeedAsync();
        }
        catch (Exception ex)
        {
            var logger = services.GetRequiredService<ILogger<Program>>();
            logger.LogError(ex, "初始化数据库时发生错误");
        }
    }
}