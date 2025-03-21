using Co.Domain.Entities.Materials.Events;
using Co.Domain.Exceptions;
using Co.Domain.SeedWork;
using Co.Domain.Utils;
using Co.Domain.ValueObjects;

namespace Co.Domain.Entities.Materials;

/// <summary>
/// 物料聚合根
/// 代表系统中的物料基本信息及相关业务规则
/// </summary>
public class Material : FullAuditedAggregateRoot
{
    #region 属性

    /// <summary>
    /// 物料编码
    /// </summary>
    public string Code { get; private set; }

    /// <summary>
    /// 物料名称
    /// </summary>
    public string Name { get; private set; }

    /// <summary>
    /// 物料简称
    /// </summary>
    public string ShortName { get; private set; }

    /// <summary>
    /// 物料描述
    /// </summary>
    public string Description { get; private set; }

    /// <summary>
    /// 物料分类ID
    /// </summary>
    public Guid CategoryId { get; private set; }

    /// <summary>
    /// 物料规格
    /// </summary>
    public Specification Specification { get; private set; }

    /// <summary>
    /// 物料单位
    /// </summary>
    public string Unit { get; private set; }

    /// <summary>
    /// 条形码
    /// </summary>
    public string Barcode { get; private set; }

    /// <summary>
    /// 物料单价
    /// </summary>
    public Money StandardCost { get; private set; }

    /// <summary>
    /// 最小库存量
    /// </summary>
    public decimal MinimumStock { get; private set; }

    /// <summary>
    /// 最大库存量
    /// </summary>
    public decimal MaximumStock { get; private set; }

    /// <summary>
    /// 安全库存量
    /// </summary>
    public decimal SafetyStock { get; private set; }

    /// <summary>
    /// 默认供应商ID
    /// </summary>
    public Guid? DefaultSupplierId { get; private set; }

    /// <summary>
    /// 采购周期(天)
    /// </summary>
    public int LeadTimeDays { get; private set; }

    /// <summary>
    /// 是否启用批次管理
    /// </summary>
    public bool BatchManaged { get; private set; }

    /// <summary>
    /// 是否启用序列号管理
    /// </summary>
    public bool SerialNumberManaged { get; private set; }

    /// <summary>
    /// 是否启用效期管理
    /// </summary>
    public bool ExpiryDateManaged { get; private set; }

    /// <summary>
    /// 物料状态
    /// </summary>
    public MaterialStatus Status { get; private set; }

    /// <summary>
    /// 图片URL
    /// </summary>
    public string ImageUrl { get; private set; }

    /// <summary>
    /// 物料标签
    /// </summary>
    public IReadOnlyList<string> Tags => _tags.AsReadOnly();

    private List<string> _tags = new List<string>();

    #endregion

    #region 构造函数

    // 私有构造函数，供EF Core使用
    private Material()
    {
    }

    /// <summary>
    /// 创建新物料
    /// </summary>
    public static Material Create(
        string code,
        string name,
        string unit,
        Guid categoryId,
        Specification specification,
        Money standardCost,
        string shortName = null,
        string description = null,
        string barcode = null,
        decimal minimumStock = 0,
        decimal maximumStock = 0,
        decimal safetyStock = 0,
        Guid? defaultSupplierId = null,
        int leadTimeDays = 0,
        bool batchManaged = false,
        bool serialNumberManaged = false,
        bool expiryDateManaged = false,
        string imageUrl = null,
        List<string> tags = null)
    {
        // 参数验证
        Guard.NullOrWhiteSpace(code, nameof(code));
        Guard.NullOrWhiteSpace(name, nameof(name));
        Guard.NullOrWhiteSpace(unit, nameof(unit));
        Guard.Default(categoryId, nameof(categoryId));
        Guard.Null(specification, nameof(specification));
        Guard.Null(standardCost, nameof(standardCost));
        Guard.Against(minimumStock, nameof(minimumStock), v => v < 0, "最小库存量不能为负数");
        Guard.Against(maximumStock, nameof(maximumStock), v => v < 0, "最大库存量不能为负数");
        Guard.Against(safetyStock, nameof(safetyStock), v => v < 0, "安全库存量不能为负数");
        Guard.Against(leadTimeDays, nameof(leadTimeDays), v => v < 0, "采购周期不能为负数");

        // 业务规则验证
        if (maximumStock > 0 && minimumStock > maximumStock)
        {
            throw new DomainException("最小库存量不能大于最大库存量");
        }

        var material = new Material
        {
            Id = SequentialGuidGenerator.NewSequentialGuid(),
            Code = code,
            Name = name,
            ShortName = shortName,
            Description = description,
            CategoryId = categoryId,
            Specification = specification,
            Unit = unit,
            Barcode = barcode,
            StandardCost = standardCost,
            MinimumStock = minimumStock,
            MaximumStock = maximumStock,
            SafetyStock = safetyStock,
            DefaultSupplierId = defaultSupplierId,
            LeadTimeDays = leadTimeDays,
            BatchManaged = batchManaged,
            SerialNumberManaged = serialNumberManaged,
            ExpiryDateManaged = expiryDateManaged,
            Status = MaterialStatus.Active,
            ImageUrl = imageUrl,
            _tags = tags ?? new List<string>()
        };

        // 添加领域事件
        material.AddDomainEvent(new MaterialCreatedEvent(material));

        return material;
    }

    #endregion

    #region 业务方法

    /// <summary>
    /// 更新物料基本信息
    /// </summary>
    public void UpdateBasicInfo(
        string name,
        string unit,
        Specification specification,
        string shortName = null,
        string description = null,
        string barcode = null,
        string imageUrl = null)
    {
        Guard.NullOrWhiteSpace(name, nameof(name));
        Guard.NullOrWhiteSpace(unit, nameof(unit));
        Guard.Null(specification, nameof(specification));

        Name = name;
        ShortName = shortName;
        Description = description;
        Unit = unit;
        Barcode = barcode;
        Specification = specification;
        ImageUrl = imageUrl;

        AddDomainEvent(new MaterialUpdatedEvent(this));
    }

    /// <summary>
    /// 更新物料库存参数
    /// </summary>
    public void UpdateStockParameters(
        decimal minimumStock,
        decimal maximumStock,
        decimal safetyStock,
        int leadTimeDays)
    {
        Guard.Against(minimumStock, nameof(minimumStock), v => v < 0, "最小库存量不能为负数");
        Guard.Against(maximumStock, nameof(maximumStock), v => v < 0, "最大库存量不能为负数");
        Guard.Against(safetyStock, nameof(safetyStock), v => v < 0, "安全库存量不能为负数");
        Guard.Against(leadTimeDays, nameof(leadTimeDays), v => v < 0, "采购周期不能为负数");

        // 业务规则验证
        if (maximumStock > 0 && minimumStock > maximumStock)
        {
            throw new DomainException("最小库存量不能大于最大库存量");
        }

        MinimumStock = minimumStock;
        MaximumStock = maximumStock;
        SafetyStock = safetyStock;
        LeadTimeDays = leadTimeDays;

        AddDomainEvent(new MaterialStockParametersUpdatedEvent(this));
    }

    /// <summary>
    /// 更新物料价格
    /// </summary>
    public void UpdatePrice(Money standardCost)
    {
        Guard.Null(standardCost, nameof(standardCost));

        StandardCost = standardCost;

        AddDomainEvent(new MaterialPriceUpdatedEvent(this, standardCost));
    }

    /// <summary>
    /// 更新物料分类
    /// </summary>
    public void UpdateCategory(Guid categoryId)
    {
        Guard.Default(categoryId, nameof(categoryId));

        CategoryId = categoryId;

        AddDomainEvent(new MaterialCategoryUpdatedEvent(this, categoryId));
    }

    /// <summary>
    /// 设置默认供应商
    /// </summary>
    public void SetDefaultSupplier(Guid supplierId)
    {
        Guard.Default(supplierId, nameof(supplierId));

        DefaultSupplierId = supplierId;
    }

    /// <summary>
    /// 移除默认供应商
    /// </summary>
    public void RemoveDefaultSupplier()
    {
        DefaultSupplierId = null;
    }

    /// <summary>
    /// 更新物料属性控制
    /// </summary>
    public void UpdateAttributeControls(
        bool batchManaged,
        bool serialNumberManaged,
        bool expiryDateManaged)
    {
        BatchManaged = batchManaged;
        SerialNumberManaged = serialNumberManaged;
        ExpiryDateManaged = expiryDateManaged;
    }

    /// <summary>
    /// 添加标签
    /// </summary>
    public void AddTag(string tag)
    {
        Guard.NullOrWhiteSpace(tag, nameof(tag));

        if (!_tags.Contains(tag))
        {
            _tags.Add(tag);
        }
    }

    /// <summary>
    /// 移除标签
    /// </summary>
    public void RemoveTag(string tag)
    {
        Guard.NullOrWhiteSpace(tag, nameof(tag));

        _tags.Remove(tag);
    }

    /// <summary>
    /// 激活物料
    /// </summary>
    public void Activate()
    {
        if (Status == MaterialStatus.Inactive)
        {
            Status = MaterialStatus.Active;
            AddDomainEvent(new MaterialStatusChangedEvent(this, MaterialStatus.Active));
        }
    }

    /// <summary>
    /// 停用物料
    /// </summary>
    public void Deactivate()
    {
        if (Status == MaterialStatus.Active)
        {
            Status = MaterialStatus.Inactive;
            AddDomainEvent(new MaterialStatusChangedEvent(this, MaterialStatus.Inactive));
        }
    }

    /// <summary>
    /// 废弃物料
    /// </summary>
    public void Obsolete()
    {
        if (Status != MaterialStatus.Obsolete)
        {
            Status = MaterialStatus.Obsolete;
            AddDomainEvent(new MaterialStatusChangedEvent(this, MaterialStatus.Obsolete));
        }
    }

    #endregion
}