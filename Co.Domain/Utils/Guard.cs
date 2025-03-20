using System;
using System.Collections.Generic;
using System.Linq;
using Co.Domain.Exceptions;

namespace Co.Domain.Utils
{
    /// <summary>
    /// 参数守卫类 - 用于简化参数验证
    /// </summary>
    public static class Guard
    {
        /// <summary>
        /// 检查字符串是否为空或空白
        /// </summary>
        public static string NullOrWhiteSpace(string value, string parameterName)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new DomainException($"参数 {parameterName} 不能为空或空白");
                
            return value;
        }

        /// <summary>
        /// 检查集合是否为空
        /// </summary>
        public static IEnumerable<T> NullOrEmpty<T>(IEnumerable<T> value, string parameterName)
        {
            if (value == null || !value.Any())
                throw new DomainException($"集合 {parameterName} 不能为空");
                
            return value;
        }

        /// <summary>
        /// 检查对象是否为空
        /// </summary>
        public static T Null<T>(T value, string parameterName) where T : class
        {
            if (value == null)
                throw new DomainException($"参数 {parameterName} 不能为空");
                
            return value;
        }

        /// <summary>
        /// 根据条件检查值是否有效
        /// </summary>
        public static T Against<T>(T value, string parameterName, Func<T, bool> predicate, string message)
        {
            if (predicate(value))
                throw new DomainException($"{message} (参数: {parameterName}, 值: {value})");
                
            return value;
        }

        /// <summary>
        /// 检查数值是否为负数
        /// </summary>
        public static decimal Negative(decimal value, string parameterName)
        {
            if (value < 0)
                throw new DomainException($"参数 {parameterName} 不能为负数，当前值: {value}");
                
            return value;
        }

        /// <summary>
        /// 检查日期是否在未来
        /// </summary>
        public static DateTime OutOfRange(DateTime value, string parameterName, DateTime minValue, DateTime maxValue)
        {
            if (value < minValue || value > maxValue)
                throw new DomainException($"日期 {parameterName} 必须在 {minValue} 和 {maxValue} 之间，当前值: {value}");
                
            return value;
        }

        /// <summary>
        /// 检查GUID是否为空
        /// </summary>
        public static Guid Default(Guid value, string parameterName)
        {
            if (value == Guid.Empty)
                throw new DomainException($"参数 {parameterName} 不能为空GUID");
                
            return value;
        }
    }
} 