using Co.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Co.Infrastructure.Data;

/// <summary>
/// 应用程序数据库上下文
/// </summary>
public class CoDbContext : IdentityDbContext<IdentityUser<Guid>, IdentityRole<Guid>, Guid>
{
    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="options">数据库上下文选项</param>
    public CoDbContext(DbContextOptions<CoDbContext> options) : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens { get; set; }
    public DbSet<TokenRevocationLog> TokenRevocationLogs { get; set; }
    public DbSet<UserLogoutLog> UserLogoutLogs { get; set; }


    /// <summary>
    /// 配置模型
    /// </summary>
    /// <param name="builder">模型构建器</param>
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // 从程序集中应用实体配置
        builder.ApplyConfigurationsFromAssembly(typeof(CoDbContext).Assembly);


        // 配置 Identity 表名
        ConfigureIdentityTable(builder);

        // 配置 OpenIddict 实体
        builder.UseOpenIddict<Guid>();
        
        // 应用实体配置
        ApplyEntityConfigurations(builder);
    }

    /// <summary>
    /// 配置 Identity 表名
    /// </summary>
    private void ConfigureIdentityTable(ModelBuilder builder)
    {
        // 自定义Identity表名前缀
        foreach (var entityType in builder.Model.GetEntityTypes())
        {
            var tableName = entityType.GetTableName();
            if (tableName != null && tableName.StartsWith("AspNet"))
            {
                entityType.SetTableName(tableName.Replace("AspNet", "Co"));
            }
        }
    }
    
    /// <summary>
    /// 应用实体配置
    /// </summary>
    /// <param name="builder">模型构建器</param>
    private void ApplyEntityConfigurations(ModelBuilder builder)
    {
        // 获取当前程序集中所有实现了 IEntityTypeConfiguration 接口的配置类
        var configTypes = typeof(CoDbContext).Assembly
            .GetTypes()
            .Where(t => !t.IsAbstract && !t.IsInterface
                && t.GetInterfaces()
                    .Any(i => i.IsGenericType
                        && i.GetGenericTypeDefinition() == typeof(IEntityTypeConfiguration<>)));

        // 应用所有配置
        foreach (var configType in configTypes)
        {
            // 创建配置实例
            var config = Activator.CreateInstance(configType);
            
            // 获取 Configure 方法
            var method = configType.GetMethod("Configure");
            
            // 获取实体类型
            var entityType = configType.GetInterfaces()
                .First(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IEntityTypeConfiguration<>))
                .GetGenericArguments()[0];
            
            // 获取 ModelBuilder.Entity<T> 方法
            var entityMethod = typeof(ModelBuilder)
                .GetMethods()
                .First(m => m.Name == "Entity" && m.IsGenericMethod)
                .MakeGenericMethod(entityType);
            
            // 调用 ModelBuilder.Entity<T>() 方法获取 EntityTypeBuilder<T>
            var entityBuilder = entityMethod.Invoke(builder, null);
            
            // 调用配置类的 Configure 方法
            method.Invoke(config, new[] { entityBuilder });
        }
    }
}