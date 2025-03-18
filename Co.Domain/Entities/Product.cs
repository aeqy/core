namespace Co.Domain.Entities;

/// <summary>
/// 产品实体
/// </summary>
public record Product
{
    /// <summary>
    /// 产品标识
    /// </summary>
    public Guid Id { get; init; } = Guid.NewGuid();
    
    /// <summary>
    /// 产品名称
    /// </summary>
    public required string Name { get; init; }
    
    /// <summary>
    /// 产品描述
    /// </summary>
    public string? Description { get; init; }
    
    /// <summary>
    /// 产品价格
    /// </summary>
    public decimal Price { get; init; }
    
    /// <summary>
    /// 产品库存
    /// </summary>
    public int Stock { get; init; }
    
    /// <summary>
    /// 产品类别
    /// </summary>
    public required string Category { get; init; }
    
    /// <summary>
    /// 创建时间
    /// </summary>
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    
    /// <summary>
    /// 最后更新时间
    /// </summary>
    public DateTime? UpdatedAt { get; init; }
    
    /// <summary>
    /// 是否已删除
    /// </summary>
    public bool IsDeleted { get; init; }
} 