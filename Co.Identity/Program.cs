using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Co.Identity.Config;
using Co.Identity.Data;
using Co.Identity.Models;
using Co.Identity.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// 添加配置
builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
builder.Configuration.AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true);
builder.Configuration.AddEnvironmentVariables();

// 添加服务
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// 添加Swagger
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Identity API", Version = "v1" });
    
    // 添加JWT Authentication
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme."
    });

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
            Array.Empty<string>()
        }
    });
});

// 添加数据库上下文
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddDbContext<OpenIddictDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// 添加Redis缓存
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
    options.InstanceName = "IdentityCache:";
});

// 添加Identity
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// 配置JWT认证
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidAudience = builder.Configuration["JWT:ValidAudience"],
        ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"] ?? throw new InvalidOperationException("JWT密钥未配置"))),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
    
    // 检查令牌是否被撤销
    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = async context =>
        {
            var tokenCacheService = context.HttpContext.RequestServices.GetRequiredService<ITokenCacheService>();
            var token = context.SecurityToken is JwtSecurityToken jwtToken ? jwtToken.RawData : null;
            
            if (token != null && await tokenCacheService.IsTokenRevokedAsync(token))
            {
                context.Fail("Token has been revoked");
            }
        }
    };
});

// 添加OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<OpenIddictDbContext>();
    })
    .AddServer(options =>
    {
        // 启用授权码流程和刷新令牌流程
        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow()
               .AllowPasswordFlow()
               .AllowClientCredentialsFlow();

        // 启用端点
        options.SetTokenEndpointUris("/connect/token")
               .SetAuthorizationEndpointUris("/connect/authorize")
               .SetIntrospectionEndpointUris("/connect/introspect")
               .SetRevocationEndpointUris("/connect/revoke");

        // 注册密钥
        options.AddEphemeralEncryptionKey()
               .AddEphemeralSigningKey();
               
        // 注册作用域
        options.RegisterScopes("openid", "profile", "email", "api");

        // 注册ASP.NET Core宿主
        options.UseAspNetCore()
               .EnableTokenEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough()
               .EnableLogoutEndpointPassthrough();
    });

// 配置HybridCache选项
builder.Services.Configure<HybridCacheOptions>(builder.Configuration.GetSection("HybridCacheOptions"));

// 添加自定义服务
builder.Services.AddTransient<IIdentityService, IdentityService>();
builder.Services.AddTransient<ITokenCacheService, RedisTokenCacheService>();
builder.Services.AddTransient<ClientConfigurationService>();
builder.Services.AddTransient<DbInitializerService>();

// 构建应用
var app = builder.Build();

// 配置HTTP请求管道
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// 确保数据库已创建并初始化
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        
        // 应用数据库迁移
        logger.LogInformation("正在应用数据库迁移...");
        var context = services.GetRequiredService<ApplicationDbContext>();
        context.Database.Migrate();
        
        var openIddictContext = services.GetRequiredService<OpenIddictDbContext>();
        openIddictContext.Database.Migrate();
        
        // 初始化数据库
        logger.LogInformation("正在初始化数据库...");
        var dbInitializer = services.GetRequiredService<DbInitializerService>();
        await dbInitializer.InitializeAsync();
        
        // 初始化OAuth客户端
        logger.LogInformation("正在初始化OAuth客户端...");
        var clientConfigService = services.GetRequiredService<ClientConfigurationService>();
        await clientConfigService.SeedClientsAsync();
        
        logger.LogInformation("数据库初始化完成");
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "初始化数据库时发生错误");
    }
}

app.Run(); 