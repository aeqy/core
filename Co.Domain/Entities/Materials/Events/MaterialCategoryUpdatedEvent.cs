using Co.Domain.Events;

namespace Co.Domain.Entities.Materials.Events;

/// <summary>
/// 物料分类更新事件
/// </summary>
public class MaterialCategoryUpdatedEvent(Material material, Guid categoryId) : DomainEvent
{
    public Material Material { get; } = material;
    public Guid CategoryId { get; } = categoryId;
}