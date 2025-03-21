using Co.Domain.Events;

namespace Co.Domain.Entities.Materials.Events;

/// <summary>
/// 物料更新事件
/// </summary>
public class MaterialUpdatedEvent(Material material) : DomainEvent
{
    public Material Material { get; } = material;
}