namespace Co.Domain.Events;

/// <summary>
/// 拥有领域事件的实体接口
/// </summary>
public interface IHasDomainEvents
{
    /// <summary>
    /// 获取领域事件集合
    /// </summary>
    IReadOnlyCollection<DomainEvent> DomainEvents { get; }

    /// <summary>
    /// 添加领域事件
    /// </summary>
    /// <param name="domainEvent">领域事件</param>
    void AddDomainEvent(DomainEvent domainEvent);

    /// <summary>
    /// 移除领域事件
    /// </summary>
    /// <param name="domainEvent">领域事件</param>
    void RemoveDomainEvent(DomainEvent domainEvent);

    /// <summary>
    /// 清除所有领域事件
    /// </summary>
    void ClearDomainEvents();
}