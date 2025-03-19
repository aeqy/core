using System.Text.Json.Serialization;

namespace Co.WebApi.Models.Auth;

/// <summary>
/// API错误响应模型
/// </summary>
public class ErrorResponse
{
    /// <summary>
    /// 错误代码
    /// </summary>
    [JsonPropertyName("error")]
    public required string Error { get; set; }

    /// <summary>
    /// 错误描述
    /// </summary>
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }
} 