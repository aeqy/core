using System;
using System.Collections.Generic;
using Co.Domain.Exceptions;
using Co.Domain.SeedWork;

namespace Co.Domain.ValueObjects
{
    /// <summary>
    /// 金额值对象 - 表示带有货币的金额值
    /// </summary>
    public class Money : ValueObject
    {
        /// <summary>
        /// 金额
        /// </summary>
        public decimal Amount { get; private set; }
        
        /// <summary>
        /// 货币代码 (ISO 4217)
        /// </summary>
        public string Currency { get; private set; }
        
        /// <summary>
        /// 私有构造函数
        /// </summary>
        private Money() { }
        
        /// <summary>
        /// 创建金额值对象
        /// </summary>
        /// <param name="amount">金额</param>
        /// <param name="currency">货币代码</param>
        public static Money Create(decimal amount, string currency)
        {
            if (string.IsNullOrWhiteSpace(currency))
                throw new DomainException("货币代码不能为空");
                
            if (currency.Length != 3)
                throw new DomainException("货币代码必须是3个字符的ISO 4217代码");
                
            return new Money
            {
                Amount = amount,
                Currency = currency.ToUpperInvariant()
            };
        }
        
        /// <summary>
        /// 创建CNY货币
        /// </summary>
        public static Money FromCNY(decimal amount)
        {
            return Create(amount, "CNY");
        }
        
        /// <summary>
        /// 创建USD货币
        /// </summary>
        public static Money FromUSD(decimal amount)
        {
            return Create(amount, "USD");
        }
        
        /// <summary>
        /// 加法运算
        /// </summary>
        public Money Add(Money money)
        {
            if (money.Currency != Currency)
                throw new DomainException($"无法进行不同货币的相加操作: {Currency} 和 {money.Currency}");
                
            return Create(Amount + money.Amount, Currency);
        }
        
        /// <summary>
        /// 减法运算
        /// </summary>
        public Money Subtract(Money money)
        {
            if (money.Currency != Currency)
                throw new DomainException($"无法进行不同货币的相减操作: {Currency} 和 {money.Currency}");
                
            return Create(Amount - money.Amount, Currency);
        }
        
        /// <summary>
        /// 乘法运算
        /// </summary>
        public Money Multiply(decimal multiplier)
        {
            return Create(Amount * multiplier, Currency);
        }
        
        /// <summary>
        /// 获取字符串表示
        /// </summary>
        public override string ToString()
        {
            return $"{Amount:F2} {Currency}";
        }
        
        /// <summary>
        /// 获取相等性比较组件
        /// </summary>
        protected override IEnumerable<object> GetEqualityComponents()
        {
            yield return Amount;
            yield return Currency;
        }
    }
} 