using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Co.Infrastructure.Data.Configurations;

/// <summary>
/// 基础实体类型配置
/// </summary>
/// <typeparam name="TEntity">实体类型</typeparam>
public abstract class BaseEntityTypeConfiguration<TEntity> : IEntityTypeConfiguration<TEntity>
    where TEntity : class
{
    /// <summary>
    /// 配置实体
    /// </summary>
    /// <param name="builder">实体类型构建器</param>
    public virtual void Configure(EntityTypeBuilder<TEntity> builder)
    {
        // 配置表名
        ConfigureTableName(builder);
        
        // 配置索引
        ConfigureIndexes(builder);
        
        // 配置关系
        ConfigureRelationships(builder);
        
        // 配置属性
        ConfigureProperties(builder);
        
        // 配置查询过滤器
        ConfigureQueryFilters(builder);
    }

    /// <summary>
    /// 配置表名
    /// </summary>
    /// <param name="builder">实体类型构建器</param>
    protected virtual void ConfigureTableName(EntityTypeBuilder<TEntity> builder)
    {
        // 默认使用实体类名作为表名
        builder.ToTable(typeof(TEntity).Name);
    }

    /// <summary>
    /// 配置索引
    /// </summary>
    /// <param name="builder">实体类型构建器</param>
    protected virtual void ConfigureIndexes(EntityTypeBuilder<TEntity> builder)
    {
        // 子类实现
    }

    /// <summary>
    /// 配置关系
    /// </summary>
    /// <param name="builder">实体类型构建器</param>
    protected virtual void ConfigureRelationships(EntityTypeBuilder<TEntity> builder)
    {
        // 子类实现
    }

    /// <summary>
    /// 配置属性
    /// </summary>
    /// <param name="builder">实体类型构建器</param>
    protected virtual void ConfigureProperties(EntityTypeBuilder<TEntity> builder)
    {
        // 子类实现
    }

    /// <summary>
    /// 配置查询过滤器
    /// </summary>
    /// <param name="builder">实体类型构建器</param>
    protected virtual void ConfigureQueryFilters(EntityTypeBuilder<TEntity> builder)
    {
        // 子类实现
    }
}