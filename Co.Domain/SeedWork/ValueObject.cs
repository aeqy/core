namespace Co.Domain.SeedWork;
/// <summary>
/// 值对象基类
/// 值对象是通过其属性值来标识的对象，没有唯一标识
/// 两个值对象如果所有属性值相等，则认为它们相等
/// </summary>
public abstract class ValueObject
{
    /// <summary>
    /// 获取用于相等性比较的属性值集合
    /// 子类必须实现此方法，返回用于判断相等的属性值
    /// </summary>
    /// <returns>属性值集合</returns>
    protected abstract IEnumerable<object> GetEqualityComponents();

    /// <summary>
    /// 重写相等性比较
    /// </summary>
    /// <param name="obj">要比较的对象</param>
    /// <returns>是否相等</returns>
    public override bool Equals(object? obj)
    {
        if (obj == null || obj.GetType() != GetType())
        {
            return false;
        }

        var other = (ValueObject)obj;
        return GetEqualityComponents().SequenceEqual(other.GetEqualityComponents());
    }

    /// <summary>
    /// 重写获取哈希码
    /// </summary>
    /// <returns>哈希码</returns>
    public override int GetHashCode()
    {
        return GetEqualityComponents()
            .Select(x => x.GetHashCode())
            .Aggregate((x, y) => x ^ y);
    }

    /// <summary>
    /// 相等运算符重载
    /// </summary>
    public static bool operator ==(ValueObject left, ValueObject right)
    {
        if (ReferenceEquals(left, null) ^ ReferenceEquals(right, null))
        {
            return false;
        }
        return ReferenceEquals(left, null) || left.Equals(right);
    }

    /// <summary>
    /// 不等运算符重载
    /// </summary>
    public static bool operator !=(ValueObject left, ValueObject right)
    {
        return !(left == right);
    }
}