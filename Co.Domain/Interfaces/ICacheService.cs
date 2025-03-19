namespace Co.Domain.Interfaces;

/// <summary>
/// 混合缓存服务接口
/// 组合使用内存缓存(一级缓存)和Redis分布式缓存(二级缓存)
/// </summary>
public interface ICacheService
{
    /// <summary>
    /// 从缓存中获取对象
    /// 优先从内存缓存获取，如不存在则从Redis获取并回填内存缓存
    /// </summary>
    /// <typeparam name="T">对象类型</typeparam>
    /// <param name="key">缓存键</param>
    /// <returns>缓存的对象，不存在则返回默认值</returns>
    Task<T?> GetAsync<T>(string key) where T : class;
    
    /// <summary>
    /// 从缓存中获取对象
    /// 优先从内存缓存获取，如不存在则从Redis获取并回填内存缓存
    /// </summary>
    /// <typeparam name="T">对象类型</typeparam>
    /// <param name="key">缓存键</param>
    /// <param name="factory">如缓存不存在则调用此工厂方法获取值</param>
    /// <param name="ttl">过期时间（秒），默认为600秒</param>
    /// <returns>缓存的对象或工厂创建的对象</returns>
    Task<T?> GetOrCreateAsync<T>(string key, Func<Task<T>> factory, int ttl = 600) where T : class?;
    
    /// <summary>
    /// 设置缓存对象
    /// 同时设置内存缓存和Redis缓存
    /// </summary>
    /// <typeparam name="T">对象类型</typeparam>
    /// <param name="key">缓存键</param>
    /// <param name="value">缓存值</param>
    /// <param name="ttl">过期时间（秒），默认为600秒</param>
    /// <returns>操作任务</returns>
    Task SetAsync<T>(string key, T value, int ttl = 600) where T : class;
    
    /// <summary>
    /// 从缓存中移除对象
    /// 同时从内存缓存和Redis缓存中移除
    /// </summary>
    /// <param name="key">缓存键</param>
    /// <returns>操作任务</returns>
    Task RemoveAsync(string key);
    
    /// <summary>
    /// 检查键是否存在
    /// 优先检查内存缓存，不存在则检查Redis缓存
    /// </summary>
    /// <param name="key">缓存键</param>
    /// <returns>是否存在</returns>
    Task<bool> ExistsAsync(string key);
    
    /// <summary>
    /// 刷新缓存过期时间
    /// 同时刷新内存缓存和Redis缓存的过期时间
    /// </summary>
    /// <param name="key">缓存键</param>
    /// <param name="ttl">新的过期时间（秒）</param>
    /// <returns>操作任务</returns>
    Task RefreshAsync(string key, int ttl = 600);
    
    /// <summary>
    /// 批量获取缓存对象
    /// 优先从内存缓存获取，缺失的键从Redis获取并回填内存缓存
    /// </summary>
    /// <typeparam name="T">对象类型</typeparam>
    /// <param name="keys">缓存键集合</param>
    /// <returns>键值对字典，不存在的键将不在结果中</returns>
    Task<IDictionary<string, T?>> GetManyAsync<T>(IEnumerable<string> keys) where T : class;
    
    /// <summary>
    /// 批量设置缓存对象
    /// 同时设置内存缓存和Redis缓存
    /// </summary>
    /// <typeparam name="T">对象类型</typeparam>
    /// <param name="keyValues">键值对字典</param>
    /// <param name="ttl">过期时间（秒），默认为600秒</param>
    /// <returns>操作任务</returns>
    Task SetManyAsync<T>(IDictionary<string, T>? keyValues, int ttl = 600) where T : class;
    
    /// <summary>
    /// 批量移除缓存对象
    /// 同时从内存缓存和Redis缓存中移除
    /// </summary>
    /// <param name="keys">缓存键集合</param>
    /// <returns>操作任务</returns>
    Task RemoveManyAsync(IEnumerable<string> keys);
    
    /// <summary>
    /// 清除所有缓存
    /// 清空内存缓存和Redis指定前缀的所有缓存
    /// </summary>
    /// <param name="keyPrefix">键前缀，为空则清除所有</param>
    /// <returns>操作任务</returns>
    Task ClearAsync(string? keyPrefix = null);
} 