using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.IO;

namespace Co.Infrastructure.Data;

public class CoDbContextFactory : IDesignTimeDbContextFactory<CoDbContext>
{
    public CoDbContext CreateDbContext(string[] args)
    {
        try
        {
            var basePath = Path.Combine(Directory.GetCurrentDirectory(), "../Co.WebApi");
            Directory.SetCurrentDirectory(basePath);

            var appSettingsPath = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json");
            var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production";
            var appSettingsEnvironmentPath = Path.Combine(Directory.GetCurrentDirectory(), $"appsettings.{environment}.json");

            Console.WriteLine($"Current Directory: {Directory.GetCurrentDirectory()}");
            Console.WriteLine($"appSettingsPath: {appSettingsPath}");
            Console.WriteLine($"appSettingsEnvironmentPath: {appSettingsEnvironmentPath}");

            Console.WriteLine($"appSettingsPath exists: {File.Exists(appSettingsPath)}");
            Console.WriteLine($"appSettingsEnvironmentPath exists: {File.Exists(appSettingsEnvironmentPath)}");

            IConfigurationRoot configuration = new ConfigurationBuilder()
                .AddJsonFile(appSettingsPath, optional: false, reloadOnChange: true)
                .AddJsonFile(appSettingsEnvironmentPath, optional: true)
                .Build();

            Console.WriteLine($"Configuration Providers: {configuration.Providers.Count()}");

            var connectionString = configuration.GetConnectionString("DefaultConnection");

            Console.WriteLine($"Connection String: {connectionString}");

            if (string.IsNullOrEmpty(connectionString))
            {
                throw new InvalidOperationException("未配置连接字符串。请检查 appsettings.json 中的 ConnectionStrings:DefaultConnection 设置。");
            }

            var optionsBuilder = new DbContextOptionsBuilder<CoDbContext>();
            optionsBuilder.UseNpgsql(connectionString)
                //.EnableSensitiveDataLogging() // 仅在开发环境启用
                .UseLoggerFactory(LoggerFactory.Create(builder =>
                {
                    builder.AddConsole();
                }));

            return new CoDbContext(optionsBuilder.Options);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"创建 DbContext 失败：{ex.Message}");
            throw new InvalidOperationException($"无法创建 DbContext：{ex.Message}", ex);
        }
    }
}