using MediatR;

namespace Co.Domain.Events
{
    /// <summary>
    /// 领域事件基类 - 所有领域事件的基类
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
        /// 构造函数
        /// </summary>
        protected DomainEvent()
        {
            Id = Guid.NewGuid();
            OccurredOn = DateTime.UtcNow;
        }
    }
} 