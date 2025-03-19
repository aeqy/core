namespace Co.WebApi.Middlewares;

public class CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
{
    private const string CorrelationIdHeaderKey = "X-Correlation-Id"; // 使用自定义的 Header

    public async Task Invoke(HttpContext context)
    {
        // 尝试从请求头中获取 Correlation ID
        if (!context.Request.Headers.TryGetValue(CorrelationIdHeaderKey, out var correlationId))
        {
            // 如果没有，则生成一个新的
            correlationId = Guid.NewGuid().ToString();
        }
        // 强制使用传入的 Correlation ID, 如果有的话。 否则使用TraceIdentifier
        context.TraceIdentifier = correlationId;

        // 将 Correlation ID 添加到响应头中
        context.Response.OnStarting(() =>
        {
            if (!context.Response.Headers.ContainsKey(CorrelationIdHeaderKey))
            {
                context.Response.Headers.Append(CorrelationIdHeaderKey, correlationId);
            }
            return Task.CompletedTask;
        });

        logger.LogDebug("CorrelationId: {CorrelationId}", correlationId); // 可选的日志记录

        await next(context);
    }
}