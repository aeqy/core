using Co.Domain.Events;

namespace Co.Domain.Entities;

/// <summary>
/// 包含领域事件的实体基类
/// </summary>
/// <typeparam name="TKey">主键类型</typeparam>
public abstract class EntityWithEvents<TKey> : Entity<TKey>, IHasDomainEvents where TKey : IEquatable<TKey>
{
    private List<DomainEvent> _domainEvents;

    /// <summary>
    /// 领域事件集合
    /// </summary>
    public IReadOnlyCollection<DomainEvent> DomainEvents => _domainEvents?.AsReadOnly();

    /// <summary>
    /// 添加领域事件
    /// </summary>
    /// <param name="domainEvent">领域事件</param>
    public void AddDomainEvent(DomainEvent domainEvent)
    {
        _domainEvents ??= new List<DomainEvent>();
        _domainEvents.Add(domainEvent);
    }

    /// <summary>
    /// 移除领域事件
    /// </summary>
    /// <param name="domainEvent">领域事件</param>
    public void RemoveDomainEvent(DomainEvent domainEvent)
    {
        _domainEvents?.Remove(domainEvent);
    }

    /// <summary>
    /// 清除所有领域事件
    /// </summary>
    public void ClearDomainEvents()
    {
        _domainEvents?.Clear();
    }
}