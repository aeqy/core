using System;
using System.Collections.Generic;
using Co.Domain.Events;

namespace Co.Domain.SeedWork
{
    /// <summary>
    /// 实体基类 - 所有领域实体的基类
    /// </summary>
    public abstract class Entity<TId>
    {
        /// <summary>
        /// 实体ID
        /// </summary>
        public TId Id { get; protected set; }

        /// <summary>
        /// 领域事件集合
        /// </summary>
        private List<DomainEvent> _domainEvents;

        /// <summary>
        /// 获取领域事件集合
        /// </summary>
        public IReadOnlyCollection<DomainEvent> DomainEvents => _domainEvents?.AsReadOnly();

        /// <summary>
        /// 添加领域事件
        /// </summary>
        /// <param name="domainEvent">要添加的领域事件</param>
        public void AddDomainEvent(DomainEvent domainEvent)
        {
            _domainEvents ??= new List<DomainEvent>();
            _domainEvents.Add(domainEvent);
        }

        /// <summary>
        /// 移除领域事件
        /// </summary>
        /// <param name="domainEvent">要移除的领域事件</param>
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

        /// <summary>
        /// 重写相等性比较
        /// </summary>
        public override bool Equals(object obj)
        {
            if (obj is not Entity<TId> other)
                return false;

            if (ReferenceEquals(this, other))
                return true;

            if (GetType() != other.GetType())
                return false;

            if (Id.Equals(default(TId)) || other.Id.Equals(default(TId)))
                return false;

            return Id.Equals(other.Id);
        }

        /// <summary>
        /// 获取哈希码
        /// </summary>
        public override int GetHashCode()
        {
            return (GetType().ToString() + Id).GetHashCode();
        }

        /// <summary>
        /// 相等性运算符
        /// </summary>
        public static bool operator ==(Entity<TId> left, Entity<TId> right)
        {
            if (left is null && right is null)
                return true;

            if (left is null || right is null)
                return false;

            return left.Equals(right);
        }

        /// <summary>
        /// 不等性运算符
        /// </summary>
        public static bool operator !=(Entity<TId> left, Entity<TId> right)
        {
            return !(left == right);
        }
    }

    /// <summary>
    /// 不指定ID类型的实体基类，默认使用Guid
    /// </summary>
    public abstract class Entity : Entity<Guid>
    {
    }
} 