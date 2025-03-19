namespace Co.Application.Common;

public class NotFoundException : Exception
{
    public NotFoundException(string message) : base(message) { }

    // 可选：添加一个构造函数，用于接收资源名称和键
    public NotFoundException(string resourceName, object key)
        : base($"Resource '{resourceName}' with key '{key}' was not found.") { }
}