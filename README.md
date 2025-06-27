# go-security

# 介绍

## 路由端点

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

## 权限表达式

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

## 集成

gin-security

## FAQ

## 贡献

