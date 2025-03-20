using Co.Domain.Events;

namespace Co.Domain.SeedWork;

/// <summary>
/// 包含领域事件的实体基类
/// 提供领域事件的管理功能，包括添加、移除和清除事件
/// </summary>
public abstract class EntityWithEvents : Entity
{
    /// <summary>
    /// 领域事件集合
    /// 使用私有字段存储，确保事件只能通过定义的方法进行管理
    /// </summary>
    private readonly List<DomainEvent> _domainEvents = new();

    /// <summary>
    /// 获取领域事件只读集合
    /// 外部代码只能读取事件，不能直接修改事件集合
    /// </summary>
    public IReadOnlyCollection<DomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    /// <summary>
    /// 默认构造函数
    /// </summary>
    protected EntityWithEvents()
    {
    }

    /// <summary>
    /// 带ID参数的构造函数
    /// </summary>
    /// <param name="id">实体ID</param>
    protected EntityWithEvents(Guid id) : base(id)
    {
    }

    /// <summary>
    /// 添加领域事件
    /// 在实体状态发生改变时调用此方法发布相应的事件
    /// </summary>
    /// <param name="eventItem">要添加的领域事件</param>
    public void AddDomainEvent(DomainEvent eventItem)
    {
        _domainEvents.Add(eventItem);
    }

    /// <summary>
    /// 移除特定的领域事件
    /// </summary>
    /// <param name="eventItem">要移除的领域事件</param>
    public void RemoveDomainEvent(DomainEvent eventItem)
    {
        _domainEvents.Remove(eventItem);
    }

    /// <summary>
    /// 清除所有领域事件
    /// 通常在事件处理完成后调用
    /// </summary>
    public void ClearDomainEvents()
    {
        _domainEvents.Clear();
    }
}