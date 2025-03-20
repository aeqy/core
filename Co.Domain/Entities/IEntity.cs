namespace Co.Domain.Entities;

/// <summary>
/// 实体接口，所有实体类都应实现此接口
/// </summary>
public interface IEntity
{
}

/// <summary>
/// 具有唯一标识符的实体接口
/// </summary>
/// <typeparam name="TKey">主键类型</typeparam>
public interface IEntity<TKey> : IEntity where TKey : IEquatable<TKey>
{
    /// <summary>
    /// 获取或设置实体的唯一标识符
    /// </summary>
    TKey Id { get; set; }
}