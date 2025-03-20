namespace Co.Domain.Enums
{
    /// <summary>
    /// 物料类型枚举
    /// </summary>
    public enum MaterialType
    {
        /// <summary>
        /// 原材料
        /// </summary>
        RawMaterial = 1,
        
        /// <summary>
        /// 半成品
        /// </summary>
        SemiFinished = 2,
        
        /// <summary>
        /// 成品
        /// </summary>
        FinishedGoods = 3,
        
        /// <summary>
        /// 包装材料
        /// </summary>
        PackagingMaterial = 4,
        
        /// <summary>
        /// 辅助材料
        /// </summary>
        Auxiliary = 5
    }
} 