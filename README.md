# go-security

[![Go report](https://goreportcard.com/badge/github.com/einsitang/go-security)](https://goreportcard.com/report/github.com/einsitang/go-security)
[![License](https://img.shields.io/github/license/einsitang/go-security)](./LICENSE)

go-security 是一个专为 Go 应用程序设计的轻量级且灵活的安全框架，旨在基于端点路由和权限表达式提供精细的访问控制。

# 🚀 概述

开发者可以通过简洁的语法为端点定义安全访问规则。支持**动态路由参数**、**通配符路径**以及将**角色**、**权限**和**组**相结合编写易于理解的**逻辑表达式**组件。

## 端点路由 endpoint

`endpoint` 格式:

**METHOD** **PATH**

example:

`GET /api/v1/users` **method** 不区分大小写，建议全大写

多种 **method** 使用 `/` 分割

`GET/POST /api/v1/users`

也可以不使用 **method** 即:

`/api/v1/users` 此时忽略 **method** , 当匹配时相当于通配所有 **method**

`/api/v1/users` match `GET /api/v1/users` `POST /api/v1/users`

### 参数

`GET /api/v1/users/:userId` // $userId

样例: `GET /api/v1/users/1` , $userId = 1

`GET /api/v1/books?category=:category` // $category

样例: `GET /api/v1/books?category=computer` , $category = computer

### 通配符

`/api/v1/action/*` // $0

样例: `/api/v1/action/delete` , $0 = delete

> 通配符仅可用于路径的末端，以避免通配多个路径
> example: 
> /imgs/*/:year/:month/:day/:fileName 
> 
> /imgs/avator/2025/05/19/xxx.jpg , $0 = avator/2025/05/19/xxx.jpg 

## 权限表达式 express

### 策略

`allow` / `deny`

### 角色/权限/组

`Role("admin")`

`Permission('doc:read')`

`Group("engineer")`

### 表达式

- 支持内置函数 `Role` / `Permission` / `Group`
- 支持 `and` / `or` 逻辑符
- 支持 `==` `!=` `>` `>=` `<` `<=` 比较语句
- 支持 `+` `-` `*` `/` `%` 数学运算符

```
# example:
allow: Role("admin") or (Permission('doc:read') and $category == "guest")
deny: Group("guest") and $category == "tech"
```

## 使用 usage

### SecurityPrincipal

创建并实现 `SecurityPrincipal` 接口,用于指定权限(Roles/Permissions/Groups)信息,可以自行通过 读取文件 / 数据库 / 分布式缓存 / 内存 等一系列方式恢复

```go
// 实现 SecurityPrincipal 接口
type principal struct {
    id          string
    roles       []string
    permissions []string
    groups      []string
}

func (p *principal) Id() string {
    return p.id
}

func (p *principal) Roles() []string {
    return p.roles
}

func (p *principal) Permissions() []string {
    return p.permissions
}

func (p *principal) Groups() []string {
    return p.groups
}
```

### Guard 警卫

`Guard` 是 go-security 里最简单的一个概念,你可以使用 **表达式** 的方式创建一个警卫,当遇到需要做权限检查时,可以直接调用 `Guard.Check(SecurityContext)` 方法进行判断是否通行(allow)

```go
guard,err := NewGuard("allow:Role('admin') and $type == 'user'")
if err != nil {
    // 表达式有误
    fmt.Printf("error: %s",err.Error())
    return
}
checked := guard.Check(&SecurityContext{
    Principal:&principal{
        roles: []string{"admin"}
        permissions: ...
        groups: ...
    },
    Params: map[string]any{
        "type": "user"
    }
})

fmt.Logf("check: %v",check) // true
```

你可以将 `Guard` 单独放在每一个需要检查的代码逻辑前

### Partol 巡逻队

你可以通过动态添加端点(endpoint)的方式组织路由，然后使用 `Partol` 自动组织不同的警卫(`Guard`)驻守不同的端点

```go
partol, err := NewPartol()
if err!=nil {
    ....
    return
}
// 添加端点
partol.AddEndpoint("/api/v1/users/:uid", "allow:Permission('users.view')")

// 为需要检查的用户组织权限信息
_principal := &principal{
    permissions: []string{"users.view"},
}

// 匹配检查
endpoint:="GET /api/v1/users/123"
checked, err := p.Check(endpoint, _principal)
if err !=nil {
    // 没匹配上路由，可以忽略pass
    log.Println(err)
}

fmt.Logf("check: %v",checked) // true
```

使用 `WithConfig` 初始化 `Partol` 实例

```go
// 通过配置文件
rulePath := "./rule.txt"
p, err := NewPartol(WithConfig(rulePath))

// 配置 principal 的权限信息
_principal := &principal{
    roles: []string{"admin"},
}

// 
endpoint := "GET /api/v1/books?category=2"
checked, err := p.Check(endpoint, _principal)
if err !=nil {
    // 没匹配上路由，可以忽略pass
    log.Println(err)
}

fmt.Logf("check: %v",checked) // true
```

规则文件 `rule.txt` 格式:

**endpoint**, **express**

```
# rule.txt
# 忽略 method
/api/v1/books?category=:category, allow:Role('admin') and $category == '2'
# 仅支持 GET 或者 POST 方法
GET/POST /api/v1/files/:year/:month/:day/:filename, allow:Role('admin') and $year == '2025' and $month == '05'
```

## 🛠️ 集成

gin-security - gin中间件 (开发中)

## 💡 FAQ

## 贡献
