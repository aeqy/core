using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Co.Domain.SeedWork;

/// <summary>
/// 生成时间有序的 GUID，适用于数据库索引优化（特别是 SQL Server 和 PostgreSQL）。
/// </summary>
public static class SequentialGuidGenerator
{
    /// <summary>
    /// 数据库GUID格式类型
    /// </summary>
    private enum SequentialGuidDatabaseType
    {
        /// <summary>
        /// SQL Server - 尾部是时间序列
        /// </summary>
        SqlServer,

        /// <summary>
        /// PostgreSQL - 头部是时间序列
        /// </summary>
        PostgreSql
    }

    // Windows API声明 
    [DllImport("rpcrt4.dll", SetLastError = true)]
    private static extern int UuidCreateSequential(out Guid guid);

    // 随机数生成器 - 线程安全
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    // 节点ID - 模拟MAC地址部分，保证同一实例生成的GUID具有连续性
    private static readonly byte[] NodeId = GenerateNodeId();

    // 序列号 - 防止在同一毫秒内生成的GUID冲突
    private static int _sequence = new Random().Next(0, 0x3FFF);
    private static long _lastTimestamp;
    private static readonly Lock Lock = new Lock();

    /// <summary>
    /// 生成一个PostgreSQL优化的顺序GUID
    /// </summary>
    public static Guid NewSequentialGuid()
    {
        return NewSequentialGuid(SequentialGuidDatabaseType.PostgreSql);
    }

    /// <summary>
    /// 生成适合指定数据库类型的顺序GUID
    /// </summary>
    /// <param name="databaseType">数据库类型</param>
    /// <returns>顺序GUID</returns>
    private static Guid NewSequentialGuid(SequentialGuidDatabaseType databaseType)
    {
        // 尝试使用Windows API (仅在Windows平台)
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            if (UuidCreateSequential(out Guid winGuid) == 0)
            {
                return FormatGuidForDatabase(winGuid, databaseType);
            }
        }

        // 自定义生成方法 (跨平台兼容)
        return CreateTimeBasedGuid(databaseType);
    }

    /// <summary>
    /// 将Windows API生成的GUID调整为适合特定数据库的格式
    /// </summary>
    private static Guid FormatGuidForDatabase(Guid guid, SequentialGuidDatabaseType databaseType)
    {
        byte[] bytes = guid.ToByteArray();

        switch (databaseType)
        {
            case SequentialGuidDatabaseType.PostgreSql:
                // PostgreSQL优化 - 时间部分在前面
                byte[] postgresBytes = new byte[16];

                // 反转前8个字节
                postgresBytes[0] = bytes[3];
                postgresBytes[1] = bytes[2];
                postgresBytes[2] = bytes[1];
                postgresBytes[3] = bytes[0];
                postgresBytes[4] = bytes[5];
                postgresBytes[5] = bytes[4];
                postgresBytes[6] = bytes[7];
                postgresBytes[7] = bytes[6];

                // 复制后8个字节
                Buffer.BlockCopy(bytes, 8, postgresBytes, 8, 8);
                return new Guid(postgresBytes);

            case SequentialGuidDatabaseType.SqlServer:
                // SQL Server已经是优化格式，不需要调整
                return guid;

            default:
                // 标准格式 - 确保网络字节序(大端)
                if (BitConverter.IsLittleEndian)
                {
                    // 调整字节序
                    Array.Reverse(bytes, 0, 4);
                    Array.Reverse(bytes, 4, 2);
                    Array.Reverse(bytes, 6, 2);
                }

                return new Guid(bytes);
        }
    }

    /// <summary>
    /// 创建RFC4122兼容的时间戳UUID (类似v1)
    /// </summary>
    private static Guid CreateTimeBasedGuid(SequentialGuidDatabaseType databaseType)
    {
        byte[] guidBytes = new byte[16];

        // 获取时间戳并防止时钟回拨
        long timestamp;
        int sequence;

        lock (Lock)
        {
            timestamp = GetTimestampFromDateTime(DateTime.UtcNow);
            if (timestamp <= _lastTimestamp)
            {
                // 时钟回拨或同一毫秒内
                timestamp = _lastTimestamp;
                _sequence = (_sequence + 1) & 0x3FFF; // 循环使用序列号
            }
            else
            {
                _sequence = new Random().Next(0, 0x3FFF);
            }

            sequence = _sequence;
            _lastTimestamp = timestamp;
        }

        byte[] timestampBytes = GetTimestampBytes(timestamp);

        // 生成剩余随机字节
        byte[] randomBytes = new byte[6];
        Rng.GetBytes(randomBytes);

        // 根据数据库类型组装GUID
        switch (databaseType)
        {
            case SequentialGuidDatabaseType.PostgreSql:
                // 时间戳在前 (方便PostgreSQL索引)
                Buffer.BlockCopy(timestampBytes, 0, guidBytes, 0, 8);

                // 后8字节: 随机 + 节点ID
                Buffer.BlockCopy(NodeId, 0, guidBytes, 8, 6);
                Buffer.BlockCopy(BitConverter.GetBytes((short)sequence), 0, guidBytes, 14, 2);

                // 设置版本为1 (基于时间)
                guidBytes[6] = (byte)((guidBytes[6] & 0x0F) | 0x10);
                // 设置变体
                guidBytes[8] = (byte)((guidBytes[8] & 0x3F) | 0x80);
                break;

            case SequentialGuidDatabaseType.SqlServer:
                // 随机+节点ID在前 (SQL Server优化)
                Buffer.BlockCopy(NodeId, 0, guidBytes, 0, 6);
                Buffer.BlockCopy(BitConverter.GetBytes((short)sequence), 0, guidBytes, 6, 2);

                // 时间戳在后8字节
                Buffer.BlockCopy(timestampBytes, 0, guidBytes, 8, 8);

                // 设置版本和变体
                guidBytes[6] = (byte)((guidBytes[6] & 0x0F) | 0x10);
                guidBytes[8] = (byte)((guidBytes[8] & 0x3F) | 0x80);
                break;

            default:
                // 标准格式 - 遵循RFC4122布局
                guidBytes[0] = timestampBytes[4];
                guidBytes[1] = timestampBytes[5];
                guidBytes[2] = timestampBytes[6];
                guidBytes[3] = timestampBytes[7];
                guidBytes[4] = timestampBytes[2];
                guidBytes[5] = timestampBytes[3];
                guidBytes[6] = (byte)((timestampBytes[0] & 0x0F) | 0x10); // 设置版本为1
                guidBytes[7] = timestampBytes[1];

                // 序列号和节点ID
                guidBytes[8] = (byte)(((sequence >> 8) & 0x3F) | 0x80); // 设置变体
                guidBytes[9] = (byte)(sequence & 0xFF);
                Buffer.BlockCopy(NodeId, 0, guidBytes, 10, 6);
                break;
        }

        return new Guid(guidBytes);
    }

    /// <summary>
    /// 从DateTime获取RFC4122时间戳
    /// </summary>
    private static long GetTimestampFromDateTime(DateTime dateTime)
    {
        // 基于1582-10-15 00:00:00 UTC (格里高利历开始)
        var gregorianStart = new DateTime(1582, 10, 15, 0, 0, 0, DateTimeKind.Utc);
        var timeSpan = dateTime - gregorianStart;

        // 转换为100纳秒间隔数 (RFC4122标准)
        return timeSpan.Ticks;
    }

    /// <summary>
    /// 将时间戳转换为字节数组
    /// </summary>
    private static byte[] GetTimestampBytes(long timestamp)
    {
        byte[] bytes = BitConverter.GetBytes(timestamp);

        // 确保是大端序 (网络字节序)
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return bytes;
    }

    /// <summary>
    /// 生成伪随机节点ID (模拟MAC地址)
    /// </summary>
    private static byte[] GenerateNodeId()
    {
        byte[] nodeId = new byte[6];

        try
        {
            // 尝试使用机器名作为种子
            string machineName = Environment.MachineName;
            byte[] machineNameBytes = System.Text.Encoding.UTF8.GetBytes(machineName);

            // 生成随机节点ID
            using (var hasher = SHA256.Create())
            {
                byte[] hash = hasher.ComputeHash(machineNameBytes);
                Buffer.BlockCopy(hash, 0, nodeId, 0, 6);
            }

            // 确保是单播地址
            nodeId[0] = (byte)(nodeId[0] | 0x01);
        }
        catch
        {
            // 如果无法获取机器名，使用纯随机值
            Rng.GetBytes(nodeId);
            nodeId[0] = (byte)(nodeId[0] | 0x01); // 确保是单播地址
        }

        return nodeId;
    }
}