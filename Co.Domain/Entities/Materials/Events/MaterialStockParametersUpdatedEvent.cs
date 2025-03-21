using Co.Domain.Events;

namespace Co.Domain.Entities.Materials.Events;

/// <summary>
/// 物料库存参数更新事件
/// </summary>
public class MaterialStockParametersUpdatedEvent(Material material) : DomainEvent
{
    public Material Material { get; } = material;
}