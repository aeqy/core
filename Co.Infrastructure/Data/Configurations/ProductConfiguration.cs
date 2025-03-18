using Co.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Co.Infrastructure.Data.Configurations;

/// <summary>
/// 产品实体配置
/// </summary>
public class ProductConfiguration : BaseEntityTypeConfiguration<Product>
{
    /// <summary>
    /// 配置表名
    /// </summary>
    protected override void ConfigureTableName(EntityTypeBuilder<Product> builder)
    {
        builder.ToTable("Products");
    }

    /// <summary>
    /// 配置索引
    /// </summary>
    protected override void ConfigureIndexes(EntityTypeBuilder<Product> builder)
    {
        // 创建产品名称的唯一索引
        builder.HasIndex(p => p.Name).IsUnique();
        
        // 创建产品类别的非唯一索引
        builder.HasIndex(p => p.Category);
        
        // 创建复合索引 (价格和库存)
        builder.HasIndex(p => new { p.Price, p.Stock });
    }

    /// <summary>
    /// 配置属性
    /// </summary>
    protected override void ConfigureProperties(EntityTypeBuilder<Product> builder)
    {
        // 配置主键
        builder.HasKey(p => p.Id);
        
        // 产品名称：必填，最大长度100
        builder.Property(p => p.Name)
            .IsRequired()
            .HasMaxLength(100);
        
        // 产品描述：可空，最大长度1000
        builder.Property(p => p.Description)
            .HasMaxLength(1000);
        
        // 产品价格：必填，精度为2位小数
        builder.Property(p => p.Price)
            .IsRequired()
            .HasPrecision(18, 2);
        
        // 产品库存：必填
        builder.Property(p => p.Stock)
            .IsRequired();
        
        // 产品类别：必填，最大长度50
        builder.Property(p => p.Category)
            .IsRequired()
            .HasMaxLength(50);
        
        // 创建时间：必填
        builder.Property(p => p.CreatedAt)
            .IsRequired();
        
        // 最后更新时间：可空
        builder.Property(p => p.UpdatedAt);
        
        // 是否已删除：必填
        builder.Property(p => p.IsDeleted)
            .IsRequired()
            .HasDefaultValue(false);
    }

    /// <summary>
    /// 配置查询过滤器
    /// </summary>
    protected override void ConfigureQueryFilters(EntityTypeBuilder<Product> builder)
    {
        // 添加软删除过滤器
        builder.HasQueryFilter(p => !p.IsDeleted);
    }
} 