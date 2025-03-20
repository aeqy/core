using MediatR;

namespace Co.Domain.Events;

/// <summary>
/// 领域事件基类
/// 所有领域事件都应继承此类
/// </summary>
public abstract class DomainEvent : INotification
{
    /// <summary>
    /// 事件ID
    /// </summary>
    public Guid Id { get; }

    /// <summary>
    /// 事件发生时间
    /// </summary>
    public DateTime OccurredOn { get; }

    /// <summary>
    /// 事件类型
    /// </summary>
    public string EventType => GetType().Name;

    /// <summary>
    /// 构造函数
    /// </summary>
    protected DomainEvent()
    {
        Id = Guid.NewGuid();
        OccurredOn = DateTime.UtcNow;
    }
}