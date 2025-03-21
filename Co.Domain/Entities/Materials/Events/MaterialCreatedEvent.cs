using Co.Domain.Events;

namespace Co.Domain.Entities.Materials.Events;

/// <summary>
/// 物料创建事件
/// </summary>
public class MaterialCreatedEvent(Material material) : DomainEvent
{
    public Material Material { get; } = material;
}