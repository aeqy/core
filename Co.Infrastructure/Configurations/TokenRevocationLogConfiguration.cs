using Co.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Co.Infrastructure.Configurations;

public class TokenRevocationLogConfiguration : IEntityTypeConfiguration<TokenRevocationLog>
{
    public void Configure(EntityTypeBuilder<TokenRevocationLog> entity)
    {
        entity.ToTable("TokenRevocationLogs");

        // 主键配置
        entity.HasKey(e => e.Id);

        // 必填字段配置
        entity.Property(e => e.UserId).IsRequired().HasMaxLength(50);
        entity.Property(e => e.TokenType).IsRequired().HasMaxLength(20);
        entity.Property(e => e.RevokedAt).IsRequired();

        // 可选字段配置
        entity.Property(e => e.Reason).HasMaxLength(500);
        entity.Property(e => e.RevokedBy).HasMaxLength(100);
        entity.Property(e => e.TokenHash).HasMaxLength(64);
        entity.Property(e => e.IpAddress).HasMaxLength(50);
        entity.Property(e => e.UserAgent).HasMaxLength(500);
        entity.Property(e => e.SessionId).HasMaxLength(100);
        entity.Property(e => e.Metadata).HasMaxLength(1000);

        // 索引配置
        entity.HasIndex(e => e.UserId);
        entity.HasIndex(e => e.RevokedAt);
        entity.HasIndex(e => e.TokenHash);

        // 审计字段默认值
        entity.Property(e => e.RevokedAt)
            .HasDefaultValueSql("CURRENT_TIMESTAMP"); // 修改这里，使用 PostgreSQL 的时间函数
    }
}