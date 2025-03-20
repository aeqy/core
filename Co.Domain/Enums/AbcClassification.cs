namespace Co.Domain.Enums
{
    /// <summary>
    /// ABC分类枚举 - 用于物料重要性分类
    /// </summary>
    public enum AbcClassification
    {
        /// <summary>
        /// A类 - 最重要物料，占用价值高，数量少
        /// </summary>
        A = 1,
        
        /// <summary>
        /// B类 - 次重要物料，价值和数量适中
        /// </summary>
        B = 2,
        
        /// <summary>
        /// C类 - 一般物料，价值低但数量多
        /// </summary>
        C = 3
    }
} 