using System.Net;
using System.Text.Json;
using Co.Application.Common;

namespace Co.WebApi.Middlewares;
public class GlobalExceptionHandlingMiddleware(
    RequestDelegate next,
    ILogger<GlobalExceptionHandlingMiddleware> logger,
    IWebHostEnvironment env)
{
    private readonly bool _includeDetails = !env.IsProduction(); // 如果不是生产环境，则包含详细信息
            // 标志，用于控制是否包含详细信息

        // 构造函数，接收 IWebHostEnvironment 参数

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/json";
            var response = context.Response;
            response.StatusCode = (int)HttpStatusCode.InternalServerError; // 默认设置为 500

            // 使用字典来构建错误响应，这样可以更方便地添加或删除属性
            var errorDetails = new Dictionary<string, object?>
            {
                ["Message"] = "An unexpected error occurred.", // 默认错误消息
                ["CorrelationId"] = context.TraceIdentifier
            };

            // 根据异常类型设置不同的状态码和错误信息
            switch (exception)
            {
                case ApplicationException e:  // 自定义应用异常
                    // 如果消息包含 "Invalid token"，则返回 403 Forbidden；否则返回 400 Bad Request
                    response.StatusCode = exception.Message.Contains("Invalid token") ? (int)HttpStatusCode.Forbidden : (int)HttpStatusCode.BadRequest;
                    errorDetails["Message"] = e.Message;
                    break;

                case FluentValidation.ValidationException e: // 使用 FluentValidation 的 ValidationException
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    errorDetails["Message"] = "One or more validation errors occurred.";
                    // 将验证错误信息格式化为更友好的结构
                    errorDetails["Errors"] = e.Errors.Select(ve => new { ve.PropertyName, ve.ErrorMessage });
                    break;

                case NotFoundException e: // 自定义的资源未找到异常
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    errorDetails["Message"] = e.Message;
                    break;
            }

            // 根据 _includeDetails 标志，决定是否包含详细信息和堆栈跟踪（仅在非生产环境中）
            if (_includeDetails)
            {
                errorDetails["Detail"] = exception.Message;
                errorDetails["StackTrace"] = exception.StackTrace;
            }

            // 记录错误日志 (始终记录完整的异常信息)
            logger.LogError(exception, "Unhandled exception: {Message}, CorrelationId: {CorrelationId}", exception.Message, context.TraceIdentifier);

            // 将错误信息序列化为 JSON
            var result = JsonSerializer.Serialize(errorDetails);
            await response.WriteAsync(result);
        }
    }