namespace Co.Domain.SeedWork;

/// <summary>
/// 完整审计接口
/// 包含基本审计和软删除功能
/// </summary>
public interface IFullAudited : IAudited, ISoftDelete
{
}