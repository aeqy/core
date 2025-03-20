using System;

namespace Co.Domain.Exceptions
{
    /// <summary>
    /// 领域异常基类 - 所有领域异常的基类
    /// </summary>
    public class DomainException : Exception
    {
        /// <summary>
        /// 默认构造函数
        /// </summary>
        public DomainException()
        {
        }

        /// <summary>
        /// 带消息的构造函数
        /// </summary>
        /// <param name="message">异常消息</param>
        public DomainException(string message) 
            : base(message)
        {
        }

        /// <summary>
        /// 带消息和内部异常的构造函数
        /// </summary>
        /// <param name="message">异常消息</param>
        /// <param name="innerException">内部异常</param>
        public DomainException(string message, Exception innerException) 
            : base(message, innerException)
        {
        }
    }
} 