using Microsoft.EntityFrameworkCore;

namespace Co.Identity.Data;

public class OpenIddictDbContext : DbContext
{
    public OpenIddictDbContext(DbContextOptions<OpenIddictDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // 使用自定义表名前缀
        builder.HasDefaultSchema("identity");
        
        // 配置OpenIddict实体
        builder.UseOpenIddict();
    }
} 