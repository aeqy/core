namespace Co.WebApi.Models;

/// <summary>
/// 通用HTTP响应模型
/// </summary>
/// <typeparam name="T">数据类型</typeparam>
public class HttpResponse<T>
{
    /// <summary>
    /// 状态码：0表示成功，其他表示失败
    /// </summary>
    public int Code { get; set; }

    /// <summary>
    /// 数据
    /// </summary>
    public T? Data { get; set; }

    /// <summary>
    /// 消息
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// 创建一个表示成功的HttpResponse实例
    /// </summary>
    /// <param name="data">数据</param>
    /// <param name="message">可选消息</param>
    /// <returns>HttpResponse实例</returns>
    public static HttpResponse<T> Success(T? data, string message = "Success")
    {
        return new HttpResponse<T> { Code = 0, Data = data, Message = message };
    }

    /// <summary>
    /// 创建一个表示失败的HttpResponse实例
    /// </summary>
    /// <param name="code">错误码</param>
    /// <param name="message">错误消息</param>
    /// <returns>HttpResponse实例</returns>
    public static HttpResponse<T> Fail(int code, string message)
    {
        return new HttpResponse<T> { Code = code, Data = default, Message = message };
    }
}