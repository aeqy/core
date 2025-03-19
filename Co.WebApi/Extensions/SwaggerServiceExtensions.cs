using System.Reflection;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerUI;

namespace Co.WebApi.Extensions;

public static class SwaggerServiceExtensions
{
    public static IServiceCollection AddSwaggerDocumentation(this IServiceCollection services)
    {
        services.AddEndpointsApiExplorer(); // 添加 Endpoints API Explorer

        services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "Co API",
                    Version = "v1",
                    Description = "API for managing text entries",
                    // Contact = new OpenApiContact // 添加联系信息
                    // {
                    //     Name = "Your Name",
                    //     Email = "your.email@example.com",
                    //     Url = new Uri("https://yourwebsite.com")
                    // },
                    // License = new OpenApiLicense // 添加许可证信息
                    // {
                    //     Name = "Use under MIT",
                    //     Url = new Uri("https://opensource.org/licenses/MIT")
                    // }
                });

                var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                c.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));

                // 添加安全定义（如果需要）
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme.",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT"
                });
                
                // 添加安全要求（如果需要）
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] {}
                    }
                });

                c.UseOneOfForPolymorphism();
                c.OrderActionsBy((apiDesc) =>
                    $"Group {apiDesc.GroupName} Action {apiDesc.HttpMethod} {apiDesc.RelativePath}");
            })
            .AddSwaggerGenNewtonsoftSupport(); // 启用对 Newtonsoft.Json 的支持

        return services;
    }

    public static IApplicationBuilder UseSwaggerDocumentation(this IApplicationBuilder app)
    {
        app.UseSwagger();
        app.UseSwaggerUI(c =>
        {
            c.SwaggerEndpoint("/swagger/v1/swagger.json", "Co API V1");
            c.DocExpansion(DocExpansion.List);
            c.DefaultModelRendering(ModelRendering.Example);
            c.DisplayRequestDuration();
            c.EnableDeepLinking();

            // 新增特性：启用深色模式
            c.DefaultModelsExpandDepth(-1); // 不自动展开 models
            c.InjectStylesheet("/swagger-ui/custom.css"); // 自定义样式表
        });

        return app;
    }
}