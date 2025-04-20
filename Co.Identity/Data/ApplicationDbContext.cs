using Co.Identity.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Co.Identity.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : IdentityDbContext<ApplicationUser, ApplicationRole, string>(options)
{
    public DbSet<AuditLog> AuditLogs { get; set; }
    public DbSet<RevokedToken> RevokedTokens { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        
        // 自定义表名前缀
        foreach (var entity in builder.Model.GetEntityTypes())
        {
            var tableName = entity.GetTableName();
            if (tableName!.StartsWith("AspNet"))
            {
                var newTableName = "Id" + tableName.Substring(6);
                entity.SetTableName(newTableName);
            }
        }

        // 配置审计日志
        builder.Entity<AuditLog>(entity =>
        {
            entity.ToTable("IdAuditLogs");
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.Action);
            
            entity.HasOne(e => e.User)
                .WithMany(u => u.AuditLogs)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        // 配置令牌撤销
        builder.Entity<RevokedToken>(entity =>
        {
            entity.ToTable("IdRevokedTokens");
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Token);
            entity.HasIndex(e => e.ExpirationTime);
            
            entity.HasOne(e => e.User)
                .WithMany(u => u.RevokedTokens)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.SetNull);
        });
    }
} 