using System.Collections.Concurrent;
using System.Text.Json;
using Co.Domain.Interfaces;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Co.Infrastructure.Services;

/// <summary>
/// 混合缓存配置选项
/// </summary>
public class HybridCacheOptions
{
    /// <summary>
    /// 键前缀，用于区分不同应用的缓存，默认为空字符串
    /// </summary>
    public string KeyPrefix { get; init; } = string.Empty;

    /// <summary>
    /// 内存缓存的默认过期时间（秒），默认为300秒（5分钟）
    /// </summary>
    public int MemoryCacheTtlSeconds { get; init; } = 300;

    /// <summary>
    /// 内存缓存过期时间与分布式缓存过期时间的比例，默认为0.5（内存缓存过期时间为分布式缓存的一半）
    /// </summary>
    public double MemoryCacheTtlRatio { get; init; } = 0.5;

    /// <summary>
    /// JSON序列化选项
    /// </summary>
    public JsonSerializerOptions JsonSerializerOptions { get; init; } = new JsonSerializerOptions
    {
        WriteIndented = false, // 不缩进输出的JSON

        PropertyNamingPolicy = JsonNamingPolicy.CamelCase // 使用驼峰命名法
    };
}

/// <summary>
/// 混合缓存服务实现。同时使用内存缓存（一级缓存）和分布式缓存（二级缓存，如 Redis）。
/// </summary>
public class HybridCacheService : ICacheService, IDisposable // 实现 ICacheService 和 IDisposable 接口
{
    private readonly IMemoryCache _memoryCache; // 内存缓存实例
    private readonly IDistributedCache _distributedCache; // 分布式缓存实例
    private readonly ILogger<HybridCacheService> _logger; // 日志记录器
    private readonly HybridCacheOptions _options; // 缓存配置选项
    private readonly SemaphoreSlim _semaphoreSlim = new(1, 1); // 用于同步批量操作的信号量（限制最大并发数为1）

    private readonly ConcurrentDictionary<string, SemaphoreSlim>
        _keySemaphores = new(); // 用于同步单个键操作的信号量字典（键为缓存键，值为对应的信号量）


    /// <summary>
    /// 构造函数，通过依赖注入获取所需的实例
    /// </summary>
    /// <param name="memoryCache">内存缓存实例</param>
    /// <param name="distributedCache">分布式缓存实例</param>
    /// <param name="logger">日志记录器</param>
    /// <param name="options">缓存配置选项</param>
    /// <exception cref="ArgumentNullException">如果任何依赖项为null，则抛出ArgumentNullException</exception>
    public HybridCacheService(
        IMemoryCache memoryCache,
        IDistributedCache distributedCache,
        ILogger<HybridCacheService> logger,
        IOptions<HybridCacheOptions>? options)
    {
        _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
        _distributedCache = distributedCache ?? throw new ArgumentNullException(nameof(distributedCache));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options)); // 获取 IOptions 中的 Value
    }


    /// <summary>
    /// 从缓存中获取指定键的值。
    /// </summary>
    /// <typeparam name="T">缓存值的类型。</typeparam>
    /// <param name="key">缓存键。</param>
    /// <returns>缓存值（如果存在），否则返回 null。</returns>
    public async Task<T?> GetAsync<T>(string key) where T : class
    {
        // 规范化缓存键（添加前缀等）
        key = NormalizeKey(key);

        // 尝试从内存缓存中获取
        if (_memoryCache.TryGetValue(key, out T? cachedValue))
        {
            _logger.LogDebug("内存缓存命中: {Key}", key);
            return cachedValue;
        }

        // 获取或创建与键关联的信号量，用于防止缓存雪崩
        var semaphore = _keySemaphores.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));

        try
        {
            // 等待信号量，确保同一时间只有一个线程可以访问特定键的分布式缓存
            await semaphore.WaitAsync();

            // 再次检查内存缓存（双重检查锁定模式）
            if (_memoryCache.TryGetValue(key, out cachedValue))
            {
                _logger.LogDebug("获取信号量后内存缓存命中: {Key}", key);
                return cachedValue;
            }

            // 从分布式缓存中获取
            var cacheBytes = await _distributedCache.GetAsync(key);
            if (cacheBytes == null)
            {
                _logger.LogDebug("缓存未命中: {Key}", key);
                return null;
            }

            try
            {
                // 反序列化从分布式缓存中获取的字节数据
                cachedValue = JsonSerializer.Deserialize<T>(cacheBytes, _options.JsonSerializerOptions);

                // 如果成功反序列化，则将值存入内存缓存
                if (cachedValue != null)
                {
                    var memoryCacheOptions = new MemoryCacheEntryOptions
                    {
                        // 设置内存缓存的过期时间
                        AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(_options.MemoryCacheTtlSeconds)
                    };
                    _memoryCache.Set(key, cachedValue, memoryCacheOptions);
                    _logger.LogDebug("分布式缓存命中，已回填内存缓存: {Key}", key);
                }

                return cachedValue;
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "反序列化分布式缓存数据失败: {Key}", key);
                // 如果反序列化失败，则从分布式缓存中移除该键的无效数据
                await _distributedCache.RemoveAsync(key);
                return null;
            }
        }
        finally
        {
            // 释放信号量
            semaphore.Release();

            // 清理不再使用的信号量
            if (semaphore.CurrentCount == 1 && _keySemaphores.ContainsKey(key))
            {
                if (_keySemaphores.TryRemove(key, out var removedSemaphore))
                {
                    removedSemaphore.Dispose();
                }
            }
        }
    }

    /// <summary>
    /// 从缓存中获取指定键的值，如果不存在，则使用提供的工厂方法创建并缓存它。
    /// </summary>
    /// <typeparam name="T">缓存值的类型。</typeparam>
    /// <param name="key">缓存键。</param>
    /// <param name="factory">用于创建值的工厂方法。</param>
    /// <param name="ttl">缓存的过期时间（秒）。</param>
    /// <returns>缓存值或工厂方法创建的值。</returns>
    public async Task<T?> GetOrCreateAsync<T>(string key, Func<Task<T>> factory, int ttl = 600) where T : class
    {
        key = NormalizeKey(key);

        if (_memoryCache.TryGetValue(key, out T? cachedValue))
        {
            _logger.LogDebug("内存缓存命中: {Key}", key);
            return cachedValue;
        }

        var semaphore = _keySemaphores.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        try
        {
            await semaphore.WaitAsync();

            if (_memoryCache.TryGetValue(key, out cachedValue)) // Double-check
            {
                _logger.LogDebug("获取信号量后内存缓存命中: {Key}", key);
                return cachedValue;
            }

            var cacheBytes = await _distributedCache.GetAsync(key);
            if (cacheBytes != null)
            {
                try
                {
                    cachedValue = JsonSerializer.Deserialize<T>(cacheBytes, _options.JsonSerializerOptions);
                    if (cachedValue != null)
                    {
                        var memoryCacheOptions = new MemoryCacheEntryOptions
                        {
                            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(
                                Math.Min(ttl * _options.MemoryCacheTtlRatio, _options.MemoryCacheTtlSeconds))
                        };
                        _memoryCache.Set(key, cachedValue, memoryCacheOptions);
                        _logger.LogDebug("分布式缓存命中，已回填内存缓存: {Key}", key);
                        return cachedValue;
                    }
                }
                catch (JsonException ex)
                {
                    _logger.LogError(ex, "反序列化分布式缓存数据失败: {Key}", key);
                    await _distributedCache.RemoveAsync(key); // Remove invalid data
                }
            }

            _logger.LogDebug("缓存未命中，正在创建新值: {Key}", key);
            var newValue = await factory();
            await SetAsync(key, newValue, ttl);

            return newValue;
        }
        finally
        {
            semaphore.Release();
            // Clean up semaphore if no longer needed
            if (semaphore.CurrentCount == 1 && _keySemaphores.ContainsKey(key))
            {
                if (_keySemaphores.TryRemove(key, out var removedSemaphore))
                {
                    removedSemaphore.Dispose();
                }
            }
        }
    }


    /// <summary>
    /// 将指定键的值设置为缓存。
    /// </summary>
    /// <typeparam name="T">缓存值的类型。</typeparam>
    /// <param name="key">缓存键。</param>
    /// <param name="value">要缓存的值。</param>
    /// <param name="ttl">缓存的过期时间（秒）。</param>
    public async Task SetAsync<T>(string key, T value, int ttl = 600) where T : class
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        key = NormalizeKey(key);

        // 将值序列化为字节数组
        var cacheBytes = JsonSerializer.SerializeToUtf8Bytes(value, _options.JsonSerializerOptions);

        // 设置分布式缓存的选项
        var distributedOptions = new DistributedCacheEntryOptions
            { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(ttl) };

        // 设置内存缓存的选项（过期时间通常比分布式缓存短）
        var memoryOptions = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow =
                TimeSpan.FromSeconds(Math.Min(ttl * _options.MemoryCacheTtlRatio, _options.MemoryCacheTtlSeconds))
        };

        // 同时设置分布式缓存和内存缓存
        await _distributedCache.SetAsync(key, cacheBytes, distributedOptions);
        _memoryCache.Set(key, value, memoryOptions);
        _logger.LogDebug("已设置缓存: {Key}, TTL: {TTL}", key, ttl);
    }


    /// <summary>
    /// 从缓存中移除指定键的值。
    /// </summary>
    /// <param name="key">缓存键。</param>
    public async Task RemoveAsync(string key)
    {
        key = NormalizeKey(key);
        _memoryCache.Remove(key); // 从内存缓存中移除
        await _distributedCache.RemoveAsync(key); // 从分布式缓存中移除
        _logger.LogDebug("已移除缓存: {Key}", key);
    }


    /// <summary>
    /// 检查缓存中是否存在指定的键。
    /// </summary>
    /// <param name="key">缓存键。</param>
    /// <returns>如果缓存中存在该键，则为 true；否则为 false。</returns>
    public async Task<bool> ExistsAsync(string key)
    {
        key = NormalizeKey(key);
        // 先检查内存缓存
        if (_memoryCache.TryGetValue(key, out _))
        {
            return true;
        }

        // 再检查分布式缓存
        var cacheBytes = await _distributedCache.GetAsync(key);
        return cacheBytes != null;
    }

    /// <summary>
    /// 刷新缓存中指定键的过期时间。
    /// </summary>
    /// <param name="key">要刷新的缓存键。</param>
    /// <param name="ttl">新的过期时间（秒）。</param>
    public async Task RefreshAsync(string key, int ttl = 600)
    {
        key = NormalizeKey(key);
        // 先尝试获取值（这会检查内存缓存，如果未命中则检查分布式缓存）
        var value = await GetAsync<object>(key); // Checks memory first, then distributed
        if (value != null)
        {
            // 如果值存在，则使用新的TTL重新设置它
            await SetAsync(key, value, ttl); // Re-sets with new TTL
        }
        else
        {
            _logger.LogDebug("刷新失败，未找到: {Key}", key);
        }
    }

    /// <summary>
    /// 批量获取多个键的值。
    /// </summary>
    /// <typeparam name="T">缓存值的类型。</typeparam>
    /// <param name="keys">要获取的键的集合。</param>
    /// <returns>一个字典，包含键和对应的值（如果存在）。</returns>
    public async Task<IDictionary<string, T?>> GetManyAsync<T>(IEnumerable<string> keys) where T : class
    {
        if (keys == null)
        {
            throw new ArgumentNullException(nameof(keys));
        }

        // 规范化键并移除重复项
        var normalizedKeys = keys.Select(NormalizeKey).Distinct().ToList();
        var result = new Dictionary<string, T?>();

        // 如果没有要获取的键，则直接返回空字典
        if (normalizedKeys.Count == 0)
        {
            return result;
        }

        // 使用信号量来限制并发
        await _semaphoreSlim.WaitAsync();
        try
        {
            var memoryHits = new Dictionary<string, T?>(); // 内存缓存命中的结果
            var missedKeys = new List<string>(); // 内存缓存中未命中的键

            // 先检查内存缓存
            foreach (var key in normalizedKeys)
            {
                if (_memoryCache.TryGetValue(key, out T? cachedValue))
                {
                    memoryHits[key] = cachedValue;
                }
                else
                {
                    missedKeys.Add(key);
                }
            }

            // 如果所有键都在内存缓存中找到，则直接返回结果
            if (missedKeys.Count == 0)
            {
                _logger.LogDebug("GetMany: 所有 {Count} 个键都在内存缓存中找到", normalizedKeys.Count);
                return memoryHits;
            }

            // 从分布式缓存中获取未命中的键
            var distributedHits = new Dictionary<string, T?>(); // 分布式缓存命中的结果
            var tasks = new List<Task>();
            foreach (var key in missedKeys)
            {
                tasks.Add(Task.Run(async () =>
                {
                    var cacheBytes = await _distributedCache.GetAsync(key);
                    if (cacheBytes != null)
                    {
                        try
                        {
                            var value = JsonSerializer.Deserialize<T>(cacheBytes, _options.JsonSerializerOptions);
                            if (value != null)
                            {
                                // 将从分布式缓存中获取的值放入内存缓存
                                var memoryOptions = new MemoryCacheEntryOptions
                                {
                                    AbsoluteExpirationRelativeToNow =
                                        TimeSpan.FromSeconds(_options.MemoryCacheTtlSeconds)
                                };
                                _memoryCache.Set(key, value, memoryOptions);
                                // 使用锁确保线程安全地添加到分布式缓存命中结果中
                                lock (distributedHits)
                                {
                                    distributedHits[key] = value;
                                }
                            }
                        }
                        catch (JsonException ex)
                        {
                            _logger.LogError(ex, "GetMany: 反序列化键 {Key} 失败", key);
                            // 移除无效的缓存条目
                            await _distributedCache.RemoveAsync(key);
                        }
                    }
                }));
            }

            // 等待所有分布式缓存获取任务完成
            await Task.WhenAll(tasks);

            // 合并内存缓存和分布式缓存的结果
            foreach (var item in memoryHits)
            {
                result[item.Key] = item.Value;
            }

            foreach (var item in distributedHits)
            {
                result[item.Key] = item.Value;
            }

            _logger.LogDebug("GetMany: 请求了 {TotalCount} 个键, 内存缓存命中 {MemoryHitCount} 个, 分布式缓存命中 {DistributedHitCount} 个",
                normalizedKeys.Count, memoryHits.Count, distributedHits.Count);

            return result;
        }
        finally
        {
            // 释放信号量
            _semaphoreSlim.Release();
        }
    }

    /// <summary>
    /// 批量设置多个键值对。
    /// </summary>
    /// <typeparam name="T">缓存值的类型。</typeparam>
    /// <param name="keyValues">要设置的键值对字典。</param>
    /// <param name="ttl">缓存的过期时间（秒）。</param>
    public async Task SetManyAsync<T>(IDictionary<string, T>? keyValues, int ttl = 600) where T : class
    {
        if (keyValues == null || keyValues.Count == 0)
        {
            return;
        }

        var tasks = new List<Task>();
        foreach (var kvp in keyValues)
        {
            tasks.Add(SetAsync(kvp.Key, kvp.Value, ttl));
        }

        await Task.WhenAll(tasks);
        _logger.LogDebug("SetMany: 设置了 {Count} 个缓存项", keyValues.Count);
    }

    /// <summary>
    /// 批量移除多个键。
    /// </summary>
    /// <param name="keys">要移除的键的集合。</param>
    public async Task RemoveManyAsync(IEnumerable<string> keys)
    {
        if (keys == null)
        {
            throw new ArgumentNullException(nameof(keys));
        }

        var normalizedKeys = keys.Select(NormalizeKey).Distinct().ToList();
        if (normalizedKeys.Count == 0)
        {
            return;
        }

        var tasks = new List<Task>();
        foreach (var key in normalizedKeys)
        {
            _memoryCache.Remove(key); // 从内存缓存中移除
            tasks.Add(_distributedCache.RemoveAsync(key)); // 从分布式缓存中移除
        }

        await Task.WhenAll(tasks);
        _logger.LogDebug("RemoveMany: 移除了 {Count} 个缓存项", normalizedKeys.Count);
    }

    /// <summary>
    /// 清除缓存。
    /// </summary>
    /// <param name="keyPrefix">要清除的键的前缀。如果为 null 或空，则清除所有缓存（取决于分布式缓存的实现）。</param>
    public async Task ClearAsync(string? keyPrefix = null)
    {
        // 清除内存缓存（如果可用）
        if (_memoryCache is MemoryCache memoryCache)
        {
            memoryCache.Compact(1.0); // 尝试完全清除内存缓存。  或者使用 reflection 调用 Clear()
            _logger.LogInformation("内存缓存已清除。");
        }
        else
        {
            _logger.LogWarning("此 IMemoryCache 实现不支持清除内存缓存。");
        }


        // 清除分布式缓存。  这需要特定于提供程序的实现。
        // 这里是一个占位符。  实际的实现需要使用分布式缓存的特定功能（例如 Redis 的 SCAN 和 DEL，或类似的机制）。
        if (!string.IsNullOrEmpty(keyPrefix))
        {
            _logger.LogWarning("使用前缀 '{KeyPrefix}' 清除分布式缓存需要特定于提供程序的实现。", keyPrefix);
            // 对于 Redis，这将涉及使用 SCAN 查找与前缀匹配的键，然后使用 DEL 删除它们。
        }
        else
        {
            _logger.LogWarning("完全清除分布式缓存需要特定于提供程序的实现，并且可能是破坏性的操作。");
            // 对于 Redis，这可能涉及 FLUSHDB（当前数据库）或 FLUSHALL（所有数据库）。
            // 警告：FLUSHALL/FLUSHDB 是破坏性操作，会删除所有数据！
        }

        await Task.CompletedTask; // 表示此方法尚未完全实现。
    }

    /// <summary>
    /// 规范化缓存键（例如，添加前缀）。
    /// </summary>
    /// <param name="key">原始缓存键。</param>
    /// <returns>规范化后的缓存键。</returns>
    /// <exception cref="ArgumentException">如果键为null或者为空，抛出异常</exception>
    private string NormalizeKey(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            throw new ArgumentException("缓存键不能为空。", nameof(key));
        }

        // 如果配置了前缀，并且键不以前缀开头，则添加前缀
        if (!string.IsNullOrEmpty(_options.KeyPrefix) && !key.StartsWith(_options.KeyPrefix))
        {
            key = $"{_options.KeyPrefix}{key}";
        }

        return key;
    }

    /// <summary>
    /// 释放资源（释放信号量）。
    /// </summary>
    public void Dispose()
    {
        _semaphoreSlim.Dispose(); // 释放批量操作的信号量
        // 释放每个键的信号量
        foreach (var semaphore in _keySemaphores.Values)
        {
            semaphore.Dispose();
        }

        _keySemaphores.Clear(); // 清空信号量字典
    }
}