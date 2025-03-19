using Co.WebApi.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Co.WebApi.Filters;

/// <summary>
/// API 响应过滤器, 自动包装成功响应
/// </summary>
public class ApiResponseFilterAttribute : ActionFilterAttribute
{
    /// <summary>
    /// 在操作执行后执行
    /// </summary>
    /// <param name="context"></param>
    public override void OnActionExecuted(ActionExecutedContext context)
    {
        if (context.Result is ObjectResult objectResult && context.Exception == null)
        {
            // 只处理成功的结果 (没有异常，且结果是 ObjectResult)
            if (objectResult.StatusCode.HasValue && objectResult.StatusCode.Value >= 200 && objectResult.StatusCode.Value < 300)
            {
                // 包装响应
                var response = HttpResponse<object>.Success(objectResult.Value);
                context.Result = new ObjectResult(response)
                {
                    StatusCode = objectResult.StatusCode // 保持原始状态码
                };
            }
        }
        // 其他类型的结果（例如 ViewResult, FileResult 等）不做处理, 或异常结果不做处理

        base.OnActionExecuted(context);
    }
}