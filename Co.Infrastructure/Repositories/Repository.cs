using System.Linq.Expressions;
using Co.Domain.Interfaces;
using Co.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Co.Infrastructure.Repositories;

/// <summary>
/// 基本仓储实现类
/// </summary>
/// <typeparam name="TEntity">实体类型</typeparam>
public class Repository<TEntity> : IRepository<TEntity> where TEntity : class
{
    protected readonly CoDbContext Context;
    protected readonly DbSet<TEntity> DbSet;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="context">数据库上下文</param>
    public Repository(CoDbContext context)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        DbSet = context.Set<TEntity>();
    }

    /// <summary>
    /// 获取所有实体
    /// </summary>
    /// <returns>实体集合</returns>
    public async Task<IEnumerable<TEntity>> GetAllAsync()
    {
        return await DbSet.ToListAsync();
    }

    /// <summary>
    /// 根据条件查询实体
    /// </summary>
    /// <param name="filter">过滤条件</param>
    /// <returns>满足条件的实体集合</returns>
    public async Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> filter)
    {
        return await DbSet.Where(filter).ToListAsync();
    }

    /// <summary>
    /// 根据主键获取实体
    /// </summary>
    /// <param name="id">主键值</param>
    /// <returns>实体对象</returns>
    public async Task<TEntity> GetByIdAsync(object id)
    {
        return await DbSet.FindAsync(id);
    }

    /// <summary>
    /// 添加实体
    /// </summary>
    /// <param name="entity">实体对象</param>
    public async Task AddAsync(TEntity entity)
    {
        await DbSet.AddAsync(entity);
    }

    /// <summary>
    /// 批量添加实体
    /// </summary>
    /// <param name="entities">实体集合</param>
    public async Task AddRangeAsync(IEnumerable<TEntity> entities)
    {
        await DbSet.AddRangeAsync(entities);
    }

    /// <summary>
    /// 更新实体
    /// </summary>
    /// <param name="entity">实体对象</param>
    public void Update(TEntity entity)
    {
        DbSet.Attach(entity);
        Context.Entry(entity).State = EntityState.Modified;
    }

    /// <summary>
    /// 批量更新实体
    /// </summary>
    /// <param name="entities">实体集合</param>
    public void UpdateRange(IEnumerable<TEntity> entities)
    {
        foreach (var entity in entities)
        {
            Update(entity);
        }
    }

    /// <summary>
    /// 删除实体
    /// </summary>
    /// <param name="entity">实体对象</param>
    public void Delete(TEntity entity)
    {
        if (Context.Entry(entity).State == EntityState.Detached)
        {
            DbSet.Attach(entity);
        }

        DbSet.Remove(entity);
    }

    /// <summary>
    /// 根据主键删除实体
    /// </summary>
    /// <param name="id">主键值</param>
    public async Task DeleteByIdAsync(object id)
    {
        var entity = await GetByIdAsync(id);
        if (entity != null)
        {
            Delete(entity);
        }
    }

    /// <summary>
    /// 批量删除实体
    /// </summary>
    /// <param name="entities">实体集合</param>
    public void DeleteRange(IEnumerable<TEntity> entities)
    {
        DbSet.RemoveRange(entities);
    }

    /// <summary>
    /// 获取查询对象
    /// </summary>
    /// <returns>查询对象</returns>
    public IQueryable<TEntity> Query()
    {
        return DbSet;
    }

    /// <summary>
    /// 检查实体是否存在
    /// </summary>
    /// <param name="filter">检查条件</param>
    /// <returns>存在返回true，否则返回false</returns>
    public async Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> filter)
    {
        return await DbSet.AnyAsync(filter);
    }
}