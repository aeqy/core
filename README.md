# core
Clean Architecture

## 类型

- `feat`: 新功能
- `fix`: 修复bug
- `docs`: 文档更改
- `style`: 不影响代码含义的更改（空格、格式化等）
- `refactor`: 既不修复bug也不添加功能的代码更改
- `perf`: 提高性能的代码更改
- `test`: 添加或修改测试
- `build`: 影响构建系统或外部依赖的更改
- `ci`: 对CI配置文件和脚本的更改
- `chore`: 其他不修改src或test文件的更改

## 范围

可选的范围应该是受影响的模块名称：
- `domain`: 领域层更改
- `application`: 应用层更改
- `infrastructure`: 基础设施层更改
- `api`: Web API层更改
- `all`: 影响所有模块的更改

## 描述

- 使用现在时态（"add"而非"added"）
- 不要首字母大写
- 不要以句号结尾
