# Co.Identity 认证服务

## 概述

Co.Identity是一个基于OpenIddict和ASP.NET Core Identity的认证服务，支持OAuth 2.0和OpenID Connect协议。此服务实现了双Token模式和单点登录功能，使用PostgreSQL作为持久化存储，Redis作为分布式缓存。

## 特性

- 基于OAuth 2.0和OpenID Connect标准
- 双Token模式（访问令牌和刷新令牌）
- 用户认证和授权
- 令牌验证和撤销
- 用户注册和角色管理
- 分布式缓存支持

## 架构

- **ASP.NET Core Identity**: 用户和角色管理
- **OpenIddict**: OAuth 2.0和OpenID Connect实现
- **PostgreSQL**: 用户数据持久化
- **Redis**: 令牌缓存和存储

## API端点

### 认证相关

- `POST /api/auth/login`: 用户登录
- `POST /api/auth/register`: 用户注册
- `POST /api/auth/refresh-token`: 刷新访问令牌
- `POST /api/auth/revoke-token`: 撤销令牌
- `GET /api/auth/validate-token`: 验证令牌

### OpenID Connect

- `POST /connect/token`: 令牌端点
- `POST /connect/revoke`: 令牌撤销端点
- `POST /connect/introspect`: 令牌内省端点

## 配置

主要配置在`appsettings.json`中：

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=postgres.co.orb.local;Port=5432;Database=co;Username=prod_user;Password=***",
    "Redis": "redis.co.orb.local:6379,password=***,ssl=False,abortConnect=False"
  },
  "HybridCacheOptions": {
    "KeyPrefix": "Id:",
    "MemoryCacheTtlSeconds": 300,
    "MemoryCacheTtlRatio": 0.5
  },
  "JWT": {
    "Secret": "***",
    "ValidIssuer": "CoIdentityService",
    "ValidAudience": "CoClients",
    "TokenExpiryMinutes": 60,
    "RefreshTokenExpiryDays": 7
  },
  "AdminUser": {
    "Email": "admin@co.orb.local",
    "Password": "Admin@123456"
  }
}
```

## 默认用户

系统初始化时会创建默认管理员用户：

- **邮箱**: admin@co.orb.local (可在appsettings.json中配置)
- **密码**: Admin@123456 (可在appsettings.json中配置)
- **角色**: Admin

## 预配置的OAuth客户端

系统初始化时会创建以下OAuth客户端：

1. **Web客户端**
   - 客户端ID: web-client
   - 客户端密钥: web-client-secret
   - 授权类型: 密码模式, 刷新令牌

2. **SPA客户端**
   - 客户端ID: spa-client
   - 客户端密钥: spa-client-secret
   - 授权类型: 授权码模式, 刷新令牌

3. **移动客户端**
   - 客户端ID: mobile-client
   - 客户端密钥: mobile-client-secret
   - 授权类型: 密码模式, 刷新令牌

4. **服务间通信客户端**
   - 客户端ID: service-client
   - 客户端密钥: service-client-secret
   - 授权类型: 客户端凭证模式

## 开发指南

### 运行项目

1. 确保已安装.NET 10.0 SDK
2. 确保PostgreSQL和Redis服务可用
3. 更新`appsettings.json`中的连接字符串
4. 运行以下命令：

```bash
cd Co.Identity
dotnet run
```

### 创建迁移

```bash
cd Co.Identity
dotnet ef migrations add <迁移名称>
dotnet ef database update
```


## 安全注意事项

- 生产环境中应使用强密钥
- 启用HTTPS
- 定期更新依赖包
- 审计日志记录所有认证活动
- 生产环境中更改默认管理员密码 