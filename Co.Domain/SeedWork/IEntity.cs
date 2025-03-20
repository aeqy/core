namespace Co.Domain.SeedWork;

/// <summary>
/// 实体接口
/// </summary>
public interface IEntity<out TKey> where TKey : IEquatable<TKey>
{
    /// <summary>
    /// 实体ID
    /// </summary>
    TKey Id { get; }
}

/// <summary>
/// 默认使用Guid作为主键的实体接口
/// </summary>
public interface IEntity : IEntity<Guid>
{
}