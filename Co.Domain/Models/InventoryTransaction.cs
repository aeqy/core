using System;
using Co.Domain.Events;
using Co.Domain.SeedWork;
using Co.Domain.Utils;
using Co.Domain.ValueObjects;

namespace Co.Domain.Models
{
    /// <summary>
    /// 库存事务类型枚举
    /// </summary>
    public enum InventoryTransactionType
    {
        /// <summary>
        /// 入库
        /// </summary>
        StockIn = 1,
        
        /// <summary>
        /// 出库
        /// </summary>
        StockOut = 2,
        
        /// <summary>
        /// 盘点调整
        /// </summary>
        Adjustment = 3,
        
        /// <summary>
        /// 库存转移
        /// </summary>
        Transfer = 4
    }
    
    /// <summary>
    /// 库存事务已创建领域事件
    /// </summary>
    public class InventoryTransactionCreatedDomainEvent : DomainEvent
    {
        /// <summary>
        /// 事务ID
        /// </summary>
        public Guid TransactionId { get; }
        
        /// <summary>
        /// 物料ID
        /// </summary>
        public Guid MaterialId { get; }
        
        /// <summary>
        /// 事务类型
        /// </summary>
        public InventoryTransactionType TransactionType { get; }
        
        /// <summary>
        /// 数量
        /// </summary>
        public decimal Quantity { get; }
        
        /// <summary>
        /// 构造函数
        /// </summary>
        public InventoryTransactionCreatedDomainEvent(
            Guid transactionId,
            Guid materialId,
            InventoryTransactionType transactionType,
            decimal quantity)
        {
            TransactionId = transactionId;
            MaterialId = materialId;
            TransactionType = transactionType;
            Quantity = quantity;
        }
    }
    
    /// <summary>
    /// 库存事务实体 - 记录物料库存变动
    /// </summary>
    public class InventoryTransaction : Entity
    {
        /// <summary>
        /// 物料ID
        /// </summary>
        public Guid MaterialId { get; private set; }
        
        /// <summary>
        /// 事务编号
        /// </summary>
        public string TransactionNumber { get; private set; }
        
        /// <summary>
        /// 事务类型
        /// </summary>
        public InventoryTransactionType TransactionType { get; private set; }
        
        /// <summary>
        /// 数量
        /// </summary>
        public decimal Quantity { get; private set; }
        
        /// <summary>
        /// 单价
        /// </summary>
        public Money UnitPrice { get; private set; }
        
        /// <summary>
        /// 总价
        /// </summary>
        public Money TotalAmount => UnitPrice.Multiply(Quantity);
        
        /// <summary>
        /// 仓库ID
        /// </summary>
        public Guid WarehouseId { get; private set; }
        
        /// <summary>
        /// 目标仓库ID (用于转移)
        /// </summary>
        public Guid? TargetWarehouseId { get; private set; }
        
        /// <summary>
        /// 参考文档号
        /// </summary>
        public string ReferenceNumber { get; private set; }
        
        /// <summary>
        /// 备注
        /// </summary>
        public string Remark { get; private set; }
        
        /// <summary>
        /// 操作人ID
        /// </summary>
        public Guid OperatorId { get; private set; }
        
        /// <summary>
        /// 交易时间
        /// </summary>
        public DateTime TransactionTime { get; private set; }
        
        /// <summary>
        /// 私有构造函数
        /// </summary>
        private InventoryTransaction() { }
        
        /// <summary>
        /// 创建库存事务
        /// </summary>
        public static InventoryTransaction Create(
            Guid materialId,
            string transactionNumber,
            InventoryTransactionType transactionType,
            decimal quantity,
            Money unitPrice,
            Guid warehouseId,
            Guid? targetWarehouseId,
            string referenceNumber,
            string remark,
            Guid operatorId)
        {
            Guard.Default(materialId, nameof(materialId));
            Guard.NullOrWhiteSpace(transactionNumber, nameof(transactionNumber));
            Guard.Null(unitPrice, nameof(unitPrice));
            Guard.Default(warehouseId, nameof(warehouseId));
            Guard.Default(operatorId, nameof(operatorId));
            
            // 特殊验证逻辑
            if (transactionType == InventoryTransactionType.Transfer && targetWarehouseId == null)
                throw new DomainException("库存转移时必须指定目标仓库");
                
            if (transactionType == InventoryTransactionType.StockOut && quantity > 0)
                quantity = -quantity; // 出库为负数
                
            var transaction = new InventoryTransaction
            {
                Id = Guid.NewGuid(),
                MaterialId = materialId,
                TransactionNumber = transactionNumber,
                TransactionType = transactionType,
                Quantity = quantity,
                UnitPrice = unitPrice,
                WarehouseId = warehouseId,
                TargetWarehouseId = targetWarehouseId,
                ReferenceNumber = referenceNumber,
                Remark = remark,
                OperatorId = operatorId,
                TransactionTime = DateTime.UtcNow
            };
            
            // 添加领域事件
            transaction.AddDomainEvent(new InventoryTransactionCreatedDomainEvent(
                transaction.Id,
                transaction.MaterialId,
                transaction.TransactionType,
                transaction.Quantity));
                
            return transaction;
        }
    }
} 