namespace Co.Identity.Config;

public class HybridCacheOptions
{
    public string KeyPrefix { get; set; } = "Id:";
    public int MemoryCacheTtlSeconds { get; set; } = 300;
    public double MemoryCacheTtlRatio { get; set; } = 0.5;
} 