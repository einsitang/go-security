<div align="center">
  <h1>go-security</h1>
</div>

[![Go report](https://goreportcard.com/badge/github.com/einsitang/go-security)](https://goreportcard.com/report/github.com/einsitang/go-security)
[![License](https://img.shields.io/github/license/einsitang/go-security)](./LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/einsitang/go-security)](https://golang.org/doc/devel/release.html)

<div align="center">
  <strong><a href="README_EN.md">English</a> | 中文</strong>
</div>

go-security 是一个专为 Go 应用程序设计的轻量级且灵活的安全框架，旨在基于端点路由和权限表达式提供精细的访问控制。

## 🚀 概述

开发者可以通过简洁的语法为端点定义安全访问规则。支持**动态路由参数**、**通配符路径**以及将**角色**、**权限**和**组**相结合编写易于理解的**逻辑表达式**组件。

## ✨ 特性

- 🔒 **灵活的权限控制** - 支持基于角色、权限和组的细粒度访问控制
- 🛣️ **动态路由匹配** - 支持路径参数、查询参数和通配符路径
- 📝 **表达式语法** - 简洁直观的权限表达式语法
- ⚡ **高性能** - 轻量级设计，编译时语法分析
- 🔧 **易于集成** - 简单的API设计，易于与现有项目集成
- 📋 **配置文件支持** - 支持通过配置文件批量定义权限规则

## 📦 安装

```bash
go get github.com/einsitang/go-security
```

## 🎯 快速开始

### 1. 定义用户主体 (SecurityPrincipal)

```go
package main

import "github.com/einsitang/go-security"

// 实现 SecurityPrincipal 接口
type User struct {
    id          string
    roles       []string
    permissions []string
    groups      []string
}

func (u *User) Id() string {
    return u.id
}

func (u *User) Roles() []string {
    return u.roles
}

func (u *User) Permissions() []string {
    return u.permissions
}

func (u *User) Groups() []string {
    return u.groups
}
```

### 2. 使用 Guard (警卫)

`guard` 是最基本的表达式应用单位，在初始化 guard 时会同时对表达式解析成抽象语法树。

使用 guard 时不需要考虑 endpoint ("端点路由")

```go
func main() {
    // 创建 guard 权限检查器
    guard, err := security.NewGuard("allow: Role('admin') and $type == 'user'")
    if err != nil {
        panic(err)
    }

    // 创建用户
    user := &User{
        id:    "123",
        roles: []string{"admin"},
    }

    // 进行权限检查
    passed, err := guard.Check(&security.SecurityContext{
        Principal: (*security.SecurityPrincipal)(user),
        Params: map[string]any{
            "type": "user",
        },
        // 此处可以按需加入自定义的参数要求
        CustomParams: map[string]string{}
    })

    if err != nil {
        // 如果产生 err ,可以忽略 passed , 按错误处理
        panic(err)
    }

    fmt.Printf("权限检查结果: %v\n", passed) // 输出: 权限检查结果: true
}
```

### 3. 使用 Sentinel (哨兵)

`sentinel` 可以定义endpoint 与 express 的关系，组成基于endpoint的路由表，从而快速命中，在你没有路由组件或者需要统一定义路由鉴权策略时使用 `sentinel` 的方式

```go
func main() {
    // 创建哨兵
    sentinel, err := security.NewSentinel()
    if err != nil {
        panic(err)
    }

    // 添加端点规则
    err = sentinel.AddEndpoint("GET /api/v1/users/:userId", "allow: Permission('users.view')")
    if err != nil {
        panic(err)
    }

    err = sentinel.AddEndpoint("/api/v1/orders?category=:category", "allow: Permission('orders.view') or $category == 'public'")
    if err != nil {
        panic(err)
    }

    // 创建用户
    user := &User{
        id:          "123",
        permissions: []string{"users.view"},
    }

    // 检查权限
    endpoint := "GET /api/v1/users/456"
    passed, err := sentinel.Check(endpoint, (*security.SecurityPrincipal)(user), nil)
    if err != nil {
        panic(err)
    }

    fmt.Printf("访问 %s 权限检查: %v\n", endpoint, passed)
}
```

## 📚 详细文档

### 端点路由格式 (Endpoint)

端点格式（pattern）：`METHOD PATH`

#### 基本格式

```
GET /api/v1/users           # 指定 GET 方法
POST /api/v1/users          # 指定 POST 方法
GET/POST /api/v1/users      # 支持多种方法，用 / 分割
/api/v1/users               # 忽略方法，匹配所有 方法
```

#### 路径参数

```
GET /api/v1/users/:userId                    # 路径参数 $userId
GET /api/v1/posts/:postId/comments/:id       # 多个路径参数
```

示例：`GET /api/v1/users/123` 匹配模式 `GET /api/v1/users/:userId`，参数 `$userId = "123"`

#### 查询参数

```
GET /api/v1/books?category=:category         # 查询参数 $category
GET /api/v1/search?q=:query&type=:type       # 多个查询参数
```

示例：`GET /api/v1/books?category=fiction` 匹配模式 `GET /api/v1/books?category=:category`，参数 `$category = "fiction"`

#### 通配符

```
/api/v1/files/*             # 通配符 $0，匹配剩余所有路径
```

示例：`/api/v1/files/2023/05/report.pdf` 匹配模式 `/api/v1/files/*`，参数 `$0 = "2023/05/report.pdf"`

> ⚠️ **注意**：通配符只能用于路径末端

### 权限表达式语法

#### 策略类型

- `allow` - 允许策略，表达式为 true 时允许访问
- `deny` - 拒绝策略，表达式为 true 时拒绝访问

#### 内置函数

| 函数                               | 描述           | 示例                                         |
| -------------------------------- | ------------ | ------------------------------------------ |
| `Role(role)`                     | 检查单个角色       | `Role('admin')`                            |
| `Roles(role1, role2, ...)`       | 检查多个角色(OR关系) | `Roles('admin', 'manager')`                |
| `Permission(perm)`               | 检查单个权限       | `Permission('users.read')`                 |
| `Permissions(perm1, perm2, ...)` | 检查多个权限(OR关系) | `Permissions('users.read', 'users.write')` |
| `Group(group)`                   | 检查单个组        | `Group('developers')`                      |
| `Groups(group1, group2, ...)`    | 检查多个组(OR关系)  | `Groups('developers', 'admins')`           |

#### 操作符

| 类型  | 操作符                              | 描述                    |
| --- | -------------------------------- | --------------------- |
| 逻辑  | `and`, `or`                      | 逻辑与、逻辑或               |
| 比较  | `==`, `!=`, `>`, `>=`, `<`, `<=` | 相等、不等、大于、大于等于、小于、小于等于 |
| 数学  | `+`, `-`, `*`, `/`, `%`          | 加、减、乘、除、取模            |
| 一元  | `!`                              | 逻辑非                   |

#### 表达式示例

```bash
# 基本角色检查
allow: Role('admin')

# 多条件组合
allow: Role('admin') or (Permission('users.read') and $category == 'public')

# 参数验证
allow: Role('manager') and $format == 'json'

# 数值计算
allow: Permission('quota.check') and $requested <= $available * 0.8
```

### 使用配置文件

#### 创建配置文件 (rule.txt)

```
# 这是注释行，以 # 开头的行会被忽略
# 格式：endpoint, expression

# 用户管理接口
GET /api/v1/users, allow: Permission('users.list')
GET /api/v1/users/:userId, allow: Permission('users.view') or $userId == 'self'
POST /api/v1/users, allow: Role('admin')
PUT /api/v1/users/:userId, allow: Role('admin') or $userId == 'self'

# 文件管理接口
GET/POST /api/v1/files/*, allow: Role('admin') and $0 != 'secret'

# 条件查询接口
/api/v1/books?category=:category, allow: Permission('books.read') or $category == 'public'
```

#### 使用配置文件初始化

```go
sentinel, err := security.NewSentinel(
    security.WithConfig("./rule.txt"),
)
if err != nil {
    panic(err)
}

// 直接使用，规则已从配置文件加载
user := &User{permissions: []string{"users.view"}}
passed, err := sentinel.Check("GET /api/v1/users/123", (*security.SecurityPrincipal)(user), nil)
```

### 自定义参数

除了路径参数和查询参数，还可以传递自定义参数用于表达式计算：

```go
customParams := map[string]string{
    "action":    "read",
    "resource":  "document",
    "timestamp": "1640995200",
}

passed, err := sentinel.Check(
    "GET /api/v1/documents/123",
    (*security.SecurityPrincipal)(user),
    customParams,
)
```

在表达式中使用自定义参数：

```bash
allow: Permission('documents.read') and #action == 'read' and #resource == 'document'
```

### 严格匹配 vs 普通匹配

#### 普通匹配 (Check)

只匹配 HTTP 方法和路径，忽略查询参数的严格匹配：

```go
// 规则: /api/books?category=:category
// 请求: GET /api/books?category=fiction&page=1
// 结果: ✅ 匹配成功，$category = "fiction"
passed, err := sentinel.Check(endpoint, user, nil)
```

#### 严格匹配 (StrictCheck)

同时匹配 HTTP 方法、路径和查询参数：

```go
// 规则: /api/books?category=:category
// 请求: GET /api/books?&page=1
// 结果: ❌ 匹配失败，因为存在额外的 category 参数
passed, err := sentinel.StrictCheck(endpoint, user, nil)

// 请求: GET /api/books?category=fiction
// 结果: ✅ 匹配成功
```

## 🔧 API 参考

### Guard 接口

```go
type Guard interface {
    // 返回原始表达式
    Express() string

    // 权限检查
    // 返回值：通过(true)/失败(false)，错误信息
    Check(context *SecurityContext) (bool, error)
}

// 创建新的 Guard 实例
func NewGuard(express string) (Guard, error)
```

### Sentinel 接口

```go
type Sentinel interface {
    // 添加端点规则
    AddEndpoint(pattern string, express string) error

    // 普通权限检查（不严格匹配查询参数）
    Check(endpoint string, principal SecurityPrincipal, customParams map[string]string) (bool, error)

    // 严格权限检查（严格匹配查询参数）
    StrictCheck(endpoint string, principal SecurityPrincipal, customParams map[string]string) (bool, error)

    // 清空所有端点规则
    CleanEndpoints()
}

// 创建新的 Sentinel 实例
func NewSentinel(options ...SentinelOption) (Sentinel, error)

// 配置选项
func WithConfig(configPath string) SentinelOption
```

### SecurityPrincipal 接口

```go
type SecurityPrincipal interface {
    Id() string
    Roles() []string
    Permissions() []string
    Groups() []string
}
```

### SecurityContext 结构

```go
type SecurityContext struct {
    Params       map[string]any    // 路径和查询参数
    Principal    SecurityPrincipal // 用户主体信息
    CustomParams map[string]string // 自定义参数
}
```

## 🛠️ 集成示例

### 与 Gin 框架集成  (简单示例)

```go
func AuthMiddleware(sentinel security.Sentinel) gin.HandlerFunc {
    return func(c *gin.Context) {
        // 构造端点字符串
        endpoint := c.Request.Method + " " + c.Request.URL.Path
        if c.Request.URL.RawQuery != "" {
            endpoint += "?" + c.Request.URL.RawQuery
        }

        // 从上下文获取用户信息
        user, exists := c.Get("user")
        if !exists {
            c.JSON(401, gin.H{"error": "未认证"})
            c.Abort()
            return
        }

        // 权限检查
        passed, err := sentinel.Check(endpoint, user.(security.SecurityPrincipal), nil)
        if err != nil {
            c.JSON(500, gin.H{"error": "权限检查失败"})
            c.Abort()
            return
        }

        if !passed {
            c.JSON(403, gin.H{"error": "权限不足"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// 使用中间件
func main() {
    sentinel, _ := security.NewSentinel(security.WithConfig("./rules.txt"))

    r := gin.Default()
    r.Use(AuthMiddleware(sentinel))

    r.GET("/api/v1/users/:id", getUserHandler)
    r.POST("/api/v1/users", createUserHandler)

    r.Run(":8080")
}
```

## 🧪 测试

运行测试：

```bash
go test ./ -v
```

基准测试：

```bash
# 基准测试
go test -bench=. -benchmem -count=5 > benchmark.txt

# CPU 性能分析
go test -bench=BenchmarkSentinel_ComplexRouting -cpuprofile=cpu.prof
go tool pprof cpu.prof

# 内存分析  
go test -bench=BenchmarkSentinel_ComplexRouting -memprofile=mem.prof
go tool pprof mem.prof

# 压力测试
go test -bench=. -benchtime=10s -cpu=1,2,4,8
```

## 🤝 贡献

欢迎贡献代码！请遵循以下步骤：

1. Fork 本仓库
2. 创建你的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交你的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启一个 Pull Request

## 💡 FAQ

### Q: 如何处理复杂的权限逻辑？

A: 可以通过组合多个表达式或使用自定义参数来实现复杂逻辑。例如：

```
allow: (Role('admin') or Role('manager')) and (#department == $userDepartment) and $action != 'delete'
```

### Q: 性能如何？

A: go-security 在初始化时编译表达式为 AST，运行时直接执行编译后的语法树，性能优异。

### Q: 支持动态权限更新吗？

A: 支持。可以调用 `CleanEndpoints()` 清空现有规则，然后重新添加规则，或者创建新的 Sentinel 实例。

### Q: 如何调试权限表达式？

A: 可以使用表达式解析器的调试功能，或者通过日志输出检查参数值和表达式执行结果。

## 📖 更多示例

查看 [examples](examples/) 目录获取更多使用示例。
