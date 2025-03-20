namespace Co.Domain.Interfaces;

/// <summary>
/// 工作单元工厂接口
/// </summary>
public interface IUnitOfWorkFactory
{
    /// <summary>
    /// 创建工作单元
    /// </summary>
    /// <returns>工作单元实例</returns>
    IUnitOfWork Create();
    
}