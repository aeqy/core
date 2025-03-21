using Co.Domain.Events;
using Co.Domain.ValueObjects;

namespace Co.Domain.Entities.Materials.Events;

/// <summary>
/// 物料价格更新事件
/// </summary>
public class MaterialPriceUpdatedEvent(Material material, Money newPrice) : DomainEvent
{
    public Material Material { get; } = material;
    public Money NewPrice { get; } = newPrice;
}