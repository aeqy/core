using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.IO;

namespace Co.WebApi.Middlewares;

public class RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
{
    private readonly RecyclableMemoryStreamManager _recyclableMemoryStreamManager = new(); // 使用可回收的内存流
        private readonly string[] _sensitivePropertyNames = ["password", "token", "secret", "creditcard"]; // 敏感属性列表

        public async Task Invoke(HttpContext context)
        {
            // 记录请求开始时间
            var stopwatch = Stopwatch.StartNew();

            // 记录请求信息
            await LogRequest(context);

            // 保留原始响应流
            var originalBodyStream = context.Response.Body;

            // 使用可回收的内存流替换响应流
            await using var responseBody = _recyclableMemoryStreamManager.GetStream();
            context.Response.Body = responseBody;

            try
            {
                // 调用下一个中间件
                await next(context);
            }
            finally
            {
                // 记录响应信息
                await LogResponse(context, stopwatch.ElapsedMilliseconds);

                // 将响应内容复制回原始流
                await responseBody.CopyToAsync(originalBodyStream);

            }
        }

        private async Task LogRequest(HttpContext context)
        {
            // 启用请求体缓冲，允许多次读取
            context.Request.EnableBuffering();

            // 使用可回收的内存流读取请求体
            await using var requestStream = _recyclableMemoryStreamManager.GetStream();
            await context.Request.Body.CopyToAsync(requestStream);

            // 读取请求体内容（并处理敏感数据）
            string requestBodyText = await ReadStreamInChunks(requestStream);
            requestBodyText = SanitizeRequestBody(requestBodyText);

            // 重置请求体流的位置
            context.Request.Body.Position = 0;

            // 构建日志消息
            var requestInfo = new
            {
                context.Request.Scheme,
                Host = context.Request.Host.Value,
                Path = context.Request.Path.Value,
                QueryString = context.Request.QueryString.Value,
                Headers = context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
                Body = requestBodyText // 处理后的请求体
            };
            //使用Serilog的结构化日志记录
            logger.LogInformation("Request: {@RequestInfo}", requestInfo);
        }


        private async Task LogResponse(HttpContext context, long elapsedMilliseconds)
        {
            // 从头开始读取响应流
            context.Response.Body.Seek(0, SeekOrigin.Begin);

            // 读取响应体内容
            string responseBodyText = await new StreamReader(context.Response.Body).ReadToEndAsync();

            // 重置响应流位置
            context.Response.Body.Seek(0, SeekOrigin.Begin);

            // 构建响应日志信息, 包含处理耗时
            var responseInfo = new
            {
                context.Response.StatusCode,
                Headers = context.Response.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
                Body = SanitizeResponseBody(responseBodyText), // 处理后的响应体,
                ElapsedTimeMs = elapsedMilliseconds
            };

           // 使用Serilog的结构化日志记录
            logger.LogInformation("Response: {@ResponseInfo}", responseInfo);

        }

        // 读取流的内容（分块读取，避免大对象）
        private static async Task<string> ReadStreamInChunks(Stream stream)
        {
            const int bufferSize = 4096; //4k
            stream.Seek(0, SeekOrigin.Begin);

            await using var textWriter = new StringWriter();
            using var reader = new StreamReader(stream, Encoding.UTF8, true, bufferSize, true);

            var buffer = new char[bufferSize];
            int bytesRead;

            while ((bytesRead = await reader.ReadAsync(buffer, 0, buffer.Length)) != 0)
            {
                await textWriter.WriteAsync(buffer, 0, bytesRead);
            }

            return textWriter.ToString();
        }

        // 处理请求体中的敏感数据
        private string SanitizeRequestBody(string requestBody)
        {
            try
            {
                // 尝试解析为 JSON
                using var document = JsonDocument.Parse(requestBody);
                var root = document.RootElement;
                return SanitizeJsonElement(root); // 递归处理 JSON
            }
            catch (JsonException)
            {
                // 如果不是 JSON，则直接返回
                return requestBody;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Error during request body sanitization.");
                return "Error during sanitization"; // 返回一个错误消息
            }
        }


        private string SanitizeResponseBody(string responseBody)
        {
            // 与 SanitizeRequestBody 类似，但可以根据需要定制不同的处理逻辑
            // 例如，可以只隐藏响应体中的部分敏感信息，而不是整个属性
            try
            {
                using var document = JsonDocument.Parse(responseBody);
                var root = document.RootElement;
                return SanitizeJsonElement(root);
            }
            catch (JsonException)
            {
                return responseBody; // 不是JSON, 原样返回.
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Error during response body sanitization.");
                return "Error during sanitization";
            }
        }

        // 递归处理 JSON，隐藏敏感属性
        private string SanitizeJsonElement(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    var replacedProperties = new List<KeyValuePair<string, JsonElement>>();
                    foreach (var property in element.EnumerateObject())
                    {
                        // 检查是否为敏感属性
                        if (_sensitivePropertyNames.Contains(property.Name.ToLowerInvariant()))
                        {
                            replacedProperties.Add(new KeyValuePair<string, JsonElement>(property.Name, JsonDocument.Parse("\"[REDACTED]\"").RootElement));
                        }
                        else
                        {
                            replacedProperties.Add(new KeyValuePair<string, JsonElement>(property.Name, JsonDocument.Parse(SanitizeJsonElement(property.Value)).RootElement));
                        }
                    }
                    // 使用匿名对象来序列化修改后的属性
                    var sanitized = JsonSerializer.Serialize(replacedProperties.ToDictionary(x => x.Key, x => x.Value));
                    return sanitized;


                case JsonValueKind.Array:
                    var replacedElements = element.EnumerateArray().Select(e => JsonDocument.Parse(SanitizeJsonElement(e)).RootElement);
                    // 使用匿名对象来序列化修改后的元素
                    return JsonSerializer.Serialize(replacedElements);

                case JsonValueKind.String:
                    return element.GetString() ?? throw new InvalidOperationException(); // 原样返回字符串

                default:
                    return element.ToString(); // 原样返回
            }
        }
    }