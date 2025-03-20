namespace Co.Domain.Entities;

/// <summary>
/// 实体基类
/// </summary>
/// <typeparam name="TKey">主键类型</typeparam>
public abstract class Entity<TKey> : IEntity<TKey> where TKey : IEquatable<TKey>
{
    /// <summary>
    /// 实体唯一标识符
    /// </summary>
    public TKey Id { get; set; }

    /// <summary>
    /// 重写Equals方法
    /// </summary>
    /// <param name="obj">比较对象</param>
    /// <returns>是否相等</returns>
    public override bool Equals(object obj)
    {
        if (obj == null || !(obj is Entity<TKey>))
            return false;

        if (ReferenceEquals(this, obj))
            return true;

        if (GetType() != obj.GetType())
            return false;

        var other = (Entity<TKey>)obj;

        if (Id == null || other.Id == null)
            return false;

        return Id.Equals(other.Id);
    }

    /// <summary>
    /// 重写GetHashCode方法
    /// </summary>
    /// <returns>哈希码</returns>
    public override int GetHashCode()
    {
        return Id == null ? 0 : Id.GetHashCode();
    }

    /// <summary>
    /// 相等运算符重载
    /// </summary>
    public static bool operator ==(Entity<TKey> left, Entity<TKey> right)
    {
        if (ReferenceEquals(left, null) && ReferenceEquals(right, null))
            return true;

        if (ReferenceEquals(left, null) || ReferenceEquals(right, null))
            return false;

        return left.Equals(right);
    }

    /// <summary>
    /// 不等运算符重载
    /// </summary>
    public static bool operator !=(Entity<TKey> left, Entity<TKey> right)
    {
        return !(left == right);
    }
}