using Co.Domain.Interfaces;

namespace Co.Domain.Entities.Materials.Repositories;

/// <summary>
/// 物料仓储接口
/// 提供物料相关的数据访问方法
/// </summary>
public interface IMaterialRepository : IRepository<Material>
{
    /// <summary>
    /// 根据编码获取物料
    /// </summary>
    Task<Material> GetByCodeAsync(string code);
        
    /// <summary>
    /// 获取指定分类的所有物料
    /// </summary>
    Task<List<Material>> GetByCategoryAsync(Guid categoryId);
        
    /// <summary>
    /// 搜索物料
    /// </summary>
    Task<List<Material>> SearchAsync(string keyword, int maxResults = 20);
        
    /// <summary>
    /// 检查物料编码是否已存在
    /// </summary>
    Task<bool> IsCodeExistsAsync(string code);
}