using System;
using System.Collections.Generic;
using Co.Domain.Enums;
using Co.Domain.Events;
using Co.Domain.Exceptions;
using Co.Domain.SeedWork;
using Co.Domain.Utils;
using Co.Domain.ValueObjects;

namespace Co.Domain.Models
{
    /// <summary>
    /// 物料创建事件 - 当创建新物料时触发
    /// </summary>
    public class MaterialCreatedDomainEvent : DomainEvent
    {
        /// <summary>
        /// 物料ID
        /// </summary>
        public Guid MaterialId { get; }
        
        /// <summary>
        /// 物料编码
        /// </summary>
        public string Code { get; }
        
        /// <summary>
        /// 物料名称
        /// </summary>
        public string Name { get; }
        
        /// <summary>
        /// 构造函数
        /// </summary>
        public MaterialCreatedDomainEvent(Guid materialId, string code, string name)
        {
            MaterialId = materialId;
            Code = code;
            Name = name;
        }
    }
    
    /// <summary>
    /// 物料实体 - 表示系统中的物料信息
    /// </summary>
    public class Material : Entity, IAggregateRoot
    {
        /// <summary>
        /// 物料编码
        /// </summary>
        public string Code { get; private set; }
        
        /// <summary>
        /// 物料名称
        /// </summary>
        public string Name { get; private set; }
        
        /// <summary>
        /// 物料类型
        /// </summary>
        public MaterialType Type { get; private set; }
        
        /// <summary>
        /// ABC分类
        /// </summary>
        public AbcClassification AbcClass { get; private set; }
        
        /// <summary>
        /// 规格信息
        /// </summary>
        public Specification Specification { get; private set; }
        
        /// <summary>
        /// 单位
        /// </summary>
        public string Unit { get; private set; }
        
        /// <summary>
        /// 单价
        /// </summary>
        public Money UnitPrice { get; private set; }
        
        /// <summary>
        /// 库存上限
        /// </summary>
        public decimal MaxStock { get; private set; }
        
        /// <summary>
        /// 库存下限
        /// </summary>
        public decimal MinStock { get; private set; }
        
        /// <summary>
        /// 安全库存
        /// </summary>
        public decimal SafetyStock { get; private set; }
        
        /// <summary>
        /// 备注
        /// </summary>
        public string Remark { get; private set; }
        
        /// <summary>
        /// 是否启用
        /// </summary>
        public bool IsActive { get; private set; }
        
        /// <summary>
        /// 创建时间
        /// </summary>
        public DateTime CreatedTime { get; private set; }
        
        /// <summary>
        /// 最后更新时间
        /// </summary>
        public DateTime LastUpdatedTime { get; private set; }
        
        /// <summary>
        /// 库存事务列表
        /// </summary>
        private readonly List<InventoryTransaction> _inventoryTransactions;
        
        /// <summary>
        /// 获取库存事务只读集合
        /// </summary>
        public IReadOnlyCollection<InventoryTransaction> InventoryTransactions => _inventoryTransactions;
        
        /// <summary>
        /// 私有构造函数
        /// </summary>
        private Material()
        {
            _inventoryTransactions = new List<InventoryTransaction>();
        }
        
        /// <summary>
        /// 创建物料
        /// </summary>
        public static Material Create(
            string code,
            string name,
            MaterialType type,
            AbcClassification abcClass,
            Specification specification,
            string unit,
            Money unitPrice,
            decimal maxStock,
            decimal minStock,
            decimal safetyStock,
            string remark = null)
        {
            Guard.NullOrWhiteSpace(code, nameof(code));
            Guard.NullOrWhiteSpace(name, nameof(name));
            Guard.NullOrWhiteSpace(unit, nameof(unit));
            Guard.Null(specification, nameof(specification));
            Guard.Null(unitPrice, nameof(unitPrice));
            Guard.Against(minStock, nameof(minStock), m => m < 0, "最小库存不能为负数");
            Guard.Against(maxStock, nameof(maxStock), m => m < minStock, "最大库存不能小于最小库存");
            Guard.Against(safetyStock, nameof(safetyStock), s => s < 0, "安全库存不能为负数");
            
            var material = new Material
            {
                Id = Guid.NewGuid(),
                Code = code,
                Name = name,
                Type = type,
                AbcClass = abcClass,
                Specification = specification,
                Unit = unit,
                UnitPrice = unitPrice,
                MaxStock = maxStock,
                MinStock = minStock,
                SafetyStock = safetyStock,
                Remark = remark,
                IsActive = true,
                CreatedTime = DateTime.UtcNow,
                LastUpdatedTime = DateTime.UtcNow
            };
            
            // 添加领域事件
            material.AddDomainEvent(new MaterialCreatedDomainEvent(material.Id, material.Code, material.Name));
            
            return material;
        }
        
        /// <summary>
        /// 更新物料基本信息
        /// </summary>
        public void UpdateBasicInfo(
            string name,
            MaterialType type,
            AbcClassification abcClass,
            Specification specification,
            string unit,
            Money unitPrice,
            decimal maxStock,
            decimal minStock,
            decimal safetyStock,
            string remark = null)
        {
            Guard.NullOrWhiteSpace(name, nameof(name));
            Guard.NullOrWhiteSpace(unit, nameof(unit));
            Guard.Null(specification, nameof(specification));
            Guard.Null(unitPrice, nameof(unitPrice));
            Guard.Against(minStock, nameof(minStock), m => m < 0, "最小库存不能为负数");
            Guard.Against(maxStock, nameof(maxStock), m => m < minStock, "最大库存不能小于最小库存");
            Guard.Against(safetyStock, nameof(safetyStock), s => s < 0, "安全库存不能为负数");
            
            Name = name;
            Type = type;
            AbcClass = abcClass;
            Specification = specification;
            Unit = unit;
            UnitPrice = unitPrice;
            MaxStock = maxStock;
            MinStock = minStock;
            SafetyStock = safetyStock;
            Remark = remark;
            LastUpdatedTime = DateTime.UtcNow;
            
            // 这里可以添加物料更新事件
        }
        
        /// <summary>
        /// 激活物料
        /// </summary>
        public void Activate()
        {
            if (IsActive)
                return;
                
            IsActive = true;
            LastUpdatedTime = DateTime.UtcNow;
            
            // 这里可以添加物料激活事件
        }
        
        /// <summary>
        /// 停用物料
        /// </summary>
        public void Deactivate()
        {
            if (!IsActive)
                return;
                
            IsActive = false;
            LastUpdatedTime = DateTime.UtcNow;
            
            // 这里可以添加物料停用事件
        }
        
        /// <summary>
        /// 添加库存事务
        /// </summary>
        public void AddInventoryTransaction(InventoryTransaction transaction)
        {
            Guard.Null(transaction, nameof(transaction));
            
            if (transaction.MaterialId != Id)
                throw new DomainException("库存事务的物料ID与当前物料不匹配");
                
            _inventoryTransactions.Add(transaction);
            
            // 这里可以添加库存变动事件
        }
    }
} 