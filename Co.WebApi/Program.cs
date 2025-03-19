using Co.WebApi.Extensions;

var builder = WebApplication.CreateBuilder(args);

// 修改服务配置方法，拆分为多个特定扩展方法
builder.Services.ConfigureServices(builder.Configuration);

var app = builder.Build();

// 调用您的扩展方法来配置应用
await app.Configure();

// 初始化数据库
if (builder.Configuration.GetValue("SeedData:Enabled", true))
{
   await ConfigureServicesExtensions.InitializeDatabaseAsync(app);
}

app.Run();