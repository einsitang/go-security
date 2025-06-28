# go-security

[![Go report](https://goreportcard.com/badge/github.com/einsitang/go-security)](https://goreportcard.com/report/github.com/einsitang/go-security)
[![License](https://img.shields.io/github/license/einsitang/go-security)](./LICENSE)

go-security is a lightweight and flexible security framework designed specifically for Go applications, aiming to provide fine-grained access control based on endpoint routing and permission expressions.

## 🚀 Overview

Developers can define secure access rules for endpoints using a concise syntax. Supports dynamic route parameters, wildcard paths, and complex permission logic combining roles, permissions, and groups with logical and comparison operators.

### Endpoint Routing

`endpoint` format:

**METHOD** **PATH**

Example:

`GET /api/v1/users` — *method is case-insensitive, uppercase is recommended*

Multiple **methods** can be separated by [/](file:///Users/einsitang/github/sevlow/go-security/README.md)

`GET/POST /api/v1/users`

You can also omit the **method**, as in:

`/api/v1/users` — *In this case, method is ignored and acts as a wildcard for all methods during matching*

#### Parameters

`GET /api/v1/users/:userId` // $userId

Example: `GET/POST /api/v1/users/1`, $userId = 1

`GET /api/v1/books?category=:category` // $category

Example: `GET /api/v1/books?category=computer`, $category = computer

#### Wildcards

`/api/v1/action/*` // $0

Example: `/api/v1/action/delete`, $0 = delete

> Wildcards can only be used at the end of a path to avoid matching multiple paths
> Example:
> /imgs/*/:year/:month/:day/:fileName 
> 
> /imgs/avatar/2025/05/19/xxx.jpg , $0 = avatar/2025/05/19/xxx.jpg 

### Permission Expressions

#### Policy

`allow` / `deny`

#### Roles / Permissions / Groups

`Role("admin")`

`Permission('doc:read')`

`Group("engineer")`

#### Expressions

- Supports built-in functions `Role` / `Permission` / `Group`
- Supports logical operators `and` / `or`
- Supports comparison operators `==` `!=` `>` `>=` `<` `<=`
- Supports mathematical operators `+` `-` [*](file:///Users/einsitang/github/sevlow/go-security/README.md) [/](file:///Users/einsitang/github/sevlow/go-security/README.md) `%`

```
# example:
allow: Role("admin") or (Permission('doc:read') and $category == "guest")
deny: Group("guest") and $category == "tech"
```

## Usage

Create and implement the [Principal](file:///Users/einsitang/github/sevlow/go-security/internal/expr/ctx/context.go#L2-L7) interface to specify user permissions (Roles/Permissions/Groups)

```go
// Implement Principal interface
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

Create a [Security](file:///Users/einsitang/github/sevlow/go-security/security.go#L16-L20) instance by loading the rule file

Rule file [rule.txt](file:///Users/einsitang/github/sevlow/go-security/rule.txt) format:

**endpoint**, **express**

```
# rule.txt
# Ignore method
/api/v1/books?category=:category, allow:Role('admin') and $category == '2'
# Only supports GET or POST methods
GET/POST /api/v1/files/:year/:month/:day/:filename, allow:Role('admin') and $year == '2025' and $month == '05'
```

Initialize the `Security` instance using `WithConfig`

```go
// Through configuration file
rulePath := "./rule.txt"
security := NewSecurity(WithConfig(rulePath))

// Configure principal's permission information
_principal := &principal{
    roles: []string{"admin"},
}
endpoint := "GET /api/v1/books?category=2"
pass, err := security.Guard(endpoint, _principal)
if err != nil {
    // No route matched, pass can be ignored
    log.Println(err)
} else {
    if pass {
        log.Println("放行")
    }else{
        log.Println("阻止")
    }
}
```

Add endpoint expressions freely

```go
security := NewSecurity()
security.RegEndpoint("/api/v1/books?category=:category", "allow:Role('admin') and $category == '2'")
security.RegEndpoint("GET/POST /api/v1/files/:year/:month/:day/:filename", "allow:Role('admin') and $year == '2025' and $month == '05'")

// Configure principal's permission information
_principal := &principal{
    roles: []string{"admin"},
}

endpoint := "GET /api/v1/books?category=2"
pass, err := security.Guard(endpoint, _principal)
if err != nil {
    // No route matched, pass can be ignored
    log.Println(err)
} else {
    if pass {
        log.Println("放行")
    }else{
        log.Println("阻止")
    }
}

```

## 🛠️ Integration

gin-security - Planned

## 💡 FAQ

## Contribution

--- 

Let me know if you need further assistance!