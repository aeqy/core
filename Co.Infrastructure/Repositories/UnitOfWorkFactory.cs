using Co.Domain.Interfaces;
using Co.Infrastructure.Data;

namespace Co.Infrastructure.Repositories;

/// <summary>
/// 工作单元工厂实现
/// </summary>
public class UnitOfWorkFactory : IUnitOfWorkFactory
{
    private readonly IServiceProvider _serviceProvider;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="serviceProvider">服务提供者</param>
    public UnitOfWorkFactory(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    }

    /// <summary>
    /// 创建工作单元
    /// </summary>
    /// <returns>工作单元实例</returns>
    public IUnitOfWork Create()
    {
        var dbContext = (CoDbContext)_serviceProvider.GetService(typeof(CoDbContext))!;
        return new UnitOfWork(dbContext);
    }
}