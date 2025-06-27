# go-security

# 介绍

## 端点路由 endpoint

### 参数
`/api/v1/users/:userId` // $userId

样例: `/api/v1/users/1` , $userId = 1

`/api/v1/books?category=:category` // $category

样例: `/api/v1/books?category=computer` , $category = computer

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

创建并实现 `Principal` 接口,用于指定 用户权限(Roles/Permissions/Groups)
```go
// 实现 Principal 接口
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

通过加载规则文件创建 `Security` 实例

规则文件 `rule.txt` 格式

endpoint,express
```
# rule.txt
/api/v1/books?category=:category, allow:Role('admin') and $category == '2'
/api/v1/files/:year/:month/:day/:filename, allow:Role('admin') and $year == '2025' and $month == '05'
```

使用 `WithConfig` 初始化 `Security` 实例
```go


// 通过配置文件
rulePath := "./rule.txt"
security := NewSecurity(WithConfig(rulePath))

// 配置 principal 的权限信息
_principal := &principal{
    roles: []string{"admin"},
}
endPoint := "/api/v1/books?category=2"
pass, err := security.Guard(endPoint, _principal)
if err !=nil {
    // 没匹配上路由，可以忽略pass
    log.Println(err)
}
if pass {
    log.Println("放行")
}else{
    log.Println("阻止")
}

```

自由添加端点表达式

```go
security := NewSecurity()
security.RegEndpoint("/api/v1/books?category=:category", "allow:Role('admin') and $category == '2'")

// 配置 principal 的权限信息
_principal := &principal{
    roles: []string{"admin"},
}

endPoint := "/api/v1/books?category=2"
pass, err := security.Guard(endPoint, _principal)
if err !=nil {
    // 没匹配上路由，可以忽略pass
    log.Println(err)
}
if pass {
    log.Println("放行")
}else{
    log.Println("阻止")
}

```

## 集成

gin-security

## FAQ

## 贡献

