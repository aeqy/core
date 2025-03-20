using System.Collections.Generic;
using System.Linq;

namespace Co.Domain.SeedWork
{
    /// <summary>
    /// 值对象基类 - 所有领域值对象的基类
    /// </summary>
    public abstract class ValueObject
    {
        /// <summary>
        /// 获取值对象相等性比较的组件
        /// 派生类必须实现此方法以提供用于相等性比较的所有组件
        /// </summary>
        protected abstract IEnumerable<object> GetEqualityComponents();

        /// <summary>
        /// 重写相等性比较
        /// </summary>
        public override bool Equals(object obj)
        {
            if (obj == null || obj.GetType() != GetType())
            {
                return false;
            }

            var other = (ValueObject)obj;

            return GetEqualityComponents().SequenceEqual(other.GetEqualityComponents());
        }

        /// <summary>
        /// 获取哈希码
        /// </summary>
        public override int GetHashCode()
        {
            return GetEqualityComponents()
                .Select(x => x != null ? x.GetHashCode() : 0)
                .Aggregate((x, y) => x ^ y);
        }

        /// <summary>
        /// 相等性运算符
        /// </summary>
        public static bool operator ==(ValueObject left, ValueObject right)
        {
            if (ReferenceEquals(left, null) && ReferenceEquals(right, null))
                return true;

            if (ReferenceEquals(left, null) || ReferenceEquals(right, null))
                return false;

            return left.Equals(right);
        }

        /// <summary>
        /// 不等性运算符
        /// </summary>
        public static bool operator !=(ValueObject left, ValueObject right)
        {
            return !(left == right);
        }

        /// <summary>
        /// 创建对象的副本
        /// </summary>
        public ValueObject GetCopy()
        {
            return this.MemberwiseClone() as ValueObject;
        }
    }
} 