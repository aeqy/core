namespace Co.Domain.SeedWork;

/// <summary>
/// 实体基类
/// 提供实体的基本功能，包括ID和相等性比较
/// </summary>
public abstract class Entity
{
    /// <summary>
    /// 实体唯一标识
    /// 使用GUID类型，确保分布式环境下的唯一性
    /// </summary>
    protected Guid Id { get; init; }

    /// <summary>
    /// 默认构造函数
    /// 自动生成优化的顺序GUID作为实体ID
    /// </summary>
    protected Entity()
    {
        Id = SequentialGuidGenerator.NewSequentialGuid();
    }

    /// <summary>
    /// 带ID参数的构造函数
    /// </summary>
    /// <param name="id">实体ID</param>
    /// <exception cref="ArgumentException">当提供的ID为空GUID时抛出</exception>
    protected Entity(Guid id)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("实体ID不能为空GUID。", nameof(id));
        }

        Id = id;
    }

    /// <summary>
    /// 重写相等性比较
    /// 两个实体相等的条件：
    /// 1. 类型相同
    /// 2. ID相同
    /// 3. ID不为空GUID
    /// </summary>
    /// <param name="obj">要比较的对象</param>
    /// <returns>是否相等</returns>
    public override bool Equals(object? obj)
    {
        if (obj is not Entity other)
            return false;

        if (ReferenceEquals(this, other))
            return true;

        if (GetType() != other.GetType())
            return false;

        if (Id == Guid.Empty || other.Id == Guid.Empty)
            return false;

        return Id == other.Id;
    }

    /// <summary>
    /// 获取哈希码
    /// 使用类型和ID的组合作为哈希码
    /// </summary>
    /// <returns>哈希码</returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(GetType(), Id);
    }

    /// <summary>
    /// 相等运算符重载
    /// </summary>
    public static bool operator ==(Entity left, Entity right)
    {
        return Equals(left, right);
    }

    /// <summary>
    /// 不等运算符重载
    /// </summary>
    public static bool operator !=(Entity left, Entity right)
    {
        return !Equals(left, right);
    }
}