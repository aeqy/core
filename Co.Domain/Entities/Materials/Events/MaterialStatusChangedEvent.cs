using Co.Domain.Events;

namespace Co.Domain.Entities.Materials.Events;

/// <summary>
/// 物料状态变更事件
/// </summary>
public class MaterialStatusChangedEvent(Material material, MaterialStatus newStatus) : DomainEvent
{
    public Material Material { get; } = material;
    public MaterialStatus NewStatus { get; } = newStatus;
}