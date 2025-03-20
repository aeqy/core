using Co.Domain.Interfaces;
using Co.Domain.Specifications;
using Co.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Co.Infrastructure.Repositories;

/// <summary>
    /// 支持规约模式的仓储实现
    /// </summary>
    /// <typeparam name="TEntity">实体类型</typeparam>
    public class SpecificationRepository<TEntity> : Repository<TEntity>, ISpecificationRepository<TEntity> where TEntity : class
    {
        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="context">数据库上下文</param>
        public SpecificationRepository(CoDbContext context) : base(context)
        {
        }

        /// <summary>
        /// 使用规约获取单个实体
        /// </summary>
        /// <param name="specification">规约对象</param>
        /// <returns>实体对象</returns>
        public async Task<TEntity> GetSingleBySpecAsync(ISpecification<TEntity> specification)
        {
            return await ApplySpecification(specification).FirstOrDefaultAsync();
        }

        /// <summary>
        /// 使用规约获取实体列表
        /// </summary>
        /// <param name="specification">规约对象</param>
        /// <returns>实体列表</returns>
        public async Task<List<TEntity>> GetListBySpecAsync(ISpecification<TEntity> specification)
        {
            return await ApplySpecification(specification).ToListAsync();
        }

        /// <summary>
        /// 使用规约获取实体数量
        /// </summary>
        /// <param name="specification">规约对象</param>
        /// <returns>实体数量</returns>
        public async Task<int> CountBySpecAsync(ISpecification<TEntity> specification)
        {
            return await ApplySpecification(specification).CountAsync();
        }

        /// <summary>
        /// 使用规约检查是否存在满足条件的实体
        /// </summary>
        /// <param name="specification">规约对象</param>
        /// <returns>是否存在</returns>
        public async Task<bool> ExistsBySpecAsync(ISpecification<TEntity> specification)
        {
            return await ApplySpecification(specification).AnyAsync();
        }

        /// <summary>
        /// 应用规约到查询
        /// </summary>
        /// <param name="specification">规约对象</param>
        /// <returns>应用规约后的查询</returns>
        private IQueryable<TEntity> ApplySpecification(ISpecification<TEntity> specification)
        {
            return SpecificationEvaluator<TEntity>.GetQuery(DbSet.AsQueryable(), specification);
        }
    }