using System.Diagnostics;

namespace Co.WebApi.Middlewares;

public class RequestResponseTimingMiddleware(RequestDelegate next, ILogger<RequestResponseTimingMiddleware> logger)
{
    public async Task Invoke(HttpContext context)
    {
        var stopwatch = Stopwatch.StartNew();

        await next(context);

        stopwatch.Stop();
        var elapsedMs = stopwatch.ElapsedMilliseconds;

        logger.LogInformation(
            "Request {Method} {Path} took {ElapsedMs}ms. CorrelationId: {CorrelationId}",
            context.Request.Method,
            context.Request.Path,
            elapsedMs,
            context.TraceIdentifier);  // 包含关联 ID
    }
}