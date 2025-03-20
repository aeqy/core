using System.Collections.Generic;
using Co.Domain.SeedWork;

namespace Co.Domain.ValueObjects
{
    /// <summary>
    /// 规格值对象 - 表示产品或物料的规格
    /// </summary>
    public class Specification : ValueObject
    {
        /// <summary>
        /// 规格尺寸 (长，单位：毫米)
        /// </summary>
        public decimal Length { get; private set; }
        
        /// <summary>
        /// 规格尺寸 (宽，单位：毫米)
        /// </summary>
        public decimal Width { get; private set; }
        
        /// <summary>
        /// 规格尺寸 (高，单位：毫米)
        /// </summary>
        public decimal Height { get; private set; }
        
        /// <summary>
        /// 重量 (单位：克)
        /// </summary>
        public decimal Weight { get; private set; }
        
        /// <summary>
        /// 颜色
        /// </summary>
        public string Color { get; private set; }
        
        /// <summary>
        /// 其他规格属性
        /// </summary>
        public string Description { get; private set; }
        
        /// <summary>
        /// 私有构造函数
        /// </summary>
        private Specification() { }
        
        /// <summary>
        /// 创建规格值对象
        /// </summary>
        public static Specification Create(
            decimal length, 
            decimal width, 
            decimal height, 
            decimal weight, 
            string color = null, 
            string description = null)
        {
            return new Specification
            {
                Length = length,
                Width = width,
                Height = height,
                Weight = weight,
                Color = color,
                Description = description
            };
        }
        
        /// <summary>
        /// 获取体积 (立方毫米)
        /// </summary>
        public decimal GetVolume()
        {
            return Length * Width * Height;
        }
        
        /// <summary>
        /// 获取相等性比较组件
        /// </summary>
        protected override IEnumerable<object> GetEqualityComponents()
        {
            yield return Length;
            yield return Width;
            yield return Height;
            yield return Weight;
            yield return Color;
            yield return Description;
        }
        
        /// <summary>
        /// 获取字符串表示
        /// </summary>
        public override string ToString()
        {
            return $"{Length}*{Width}*{Height}mm, {Weight}g, {Color}, {Description}";
        }
    }
} 