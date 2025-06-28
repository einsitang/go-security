# go-security

[![Go report](https://goreportcard.com/badge/github.com/einsitang/go-security)](https://goreportcard.com/report/github.com/einsitang/go-security)
[![License](https://img.shields.io/github/license/einsitang/go-security)](./LICENSE)

**go-security** is a lightweight and flexible security framework designed for Go applications. Its goal is to provide fine-grained access control based on endpoint routing and permission expressions.

## 🚀 Overview

Developers can define secure access rules for endpoints using concise syntax. It supports **dynamic route parameters**, **wildcard paths**, and combining **roles**, **permissions**, and **groups** into easy-to-understand **logical expressions**.

---

### Endpoint Routing

The `endpoint` format:

**METHOD** **PATH**

Example:

`GET /api/v1/users` —— The **method** is case-insensitive, but it's recommended to use uppercase.

Multiple **methods** can be specified by separating them with [/](file:///Users/einsitang/github/sevlow/go-security/README.md).

`GET/POST /api/v1/users`

You can also omit the **method**:

`/api/v1/users` —— This matches all methods when matching, equivalent to wildcard method.

`/api/v1/users` matches both `GET /api/v1/users` and `POST /api/v1/users`.

#### Parameters

`GET /api/v1/users/:userId` // $userId

Example: `GET /api/v1/users/1`, $userId = 1

`GET /api/v1/books?category=:category` // $category

Example: `GET /api/v1/books?category=computer`, $category = computer

#### Wildcards

`/api/v1/action/*` // $0

Example: `/api/v1/action/delete`, $0 = delete

> Wildcards can only be used at the end of a path to avoid matching multiple segments.
> 
> Example:
> `/imgs/*/:year/:month/:day/:fileName`
> 
> For `/imgs/avatar/2025/05/19/xxx.jpg`, $0 = `avatar/2025/05/19/xxx.jpg`

---

### Permission Expressions ([express](file:///Users/einsitang/github/sevlow/go-security/guard.go#L15-L15))

#### Policy

`allow` / `deny`

#### Roles / Permissions / Groups

`Role("admin")`

`Permission('doc:read')`

`Group("engineer")`

#### Expression Syntax

- Built-in functions supported: `Role`, `Permission`, `Group`
- Logical operators: `and`, `or`
- Comparison operators: `==`, `!=`, `>`, `>=`, `<`, `<=`
- Math operators: `+`, `-`, [*](file:///Users/einsitang/github/sevlow/go-security/README.md), [/](file:///Users/einsitang/github/sevlow/go-security/README.md), `%`

```
# example:
allow: Role("admin") or (Permission('doc:read') and $category == "guest")
deny: Group("guest") and $category == "tech"
```

---

## Usage

### SecurityPrincipal

Create and implement the `SecurityPrincipal` interface to specify role, permission, and group information. You can retrieve this data from files, databases, distributed caches, memory, etc.

```go
// Implement the SecurityPrincipal interface
type principal struct {
    id          string
    roles       []string
    permissions []string
    groups      []string
}

func (p *principal) Id() string {
    return p.id
}

func (p *principal) Roles() string[] {
    return p.roles
}

func (p *principal) Permissions() string[] {
    return p.permissions
}

func (p *principal) Groups() string[] {
    return p.groups
}
```

### Guard

A [Guard](file:///Users/einsitang/github/sevlow/go-security/guard.go#L9-L12) is the simplest concept in go-security. You can create a guard using an **expression**, and call [Guard.Check(SecurityContext)](file:///Users/einsitang/github/sevlow/go-security/guard.go#L11-L11) to determine whether access is allowed.

```go
guard, err := NewGuard("allow:Role('admin') and $type == 'user'")
if err != nil {
    // Invalid expression
    fmt.Printf("error: %s", err.Error())
    return
}
checked := guard.Check(&SecurityContext{
    Principal: &principal{
        roles: []string{"admin"}
        permissions: ...
        groups: ...
    },
    Params: map[string]any{
        "type": "user"
    }
})

fmt.Logf("check: %v", checked) // true
```

You can place [Guard](file:///Users/einsitang/github/sevlow/go-security/guard.go#L9-L12) checks before any logic that requires authorization.

### Patrol

You can organize routes dynamically by adding endpoints, and then use `Patrol` to automatically assign different guards to different endpoints.

```go
patrol, err := NewPatrol()
if err != nil {
    ....
    return
}
// Add an endpoint
patrol.AddEndpoint("/api/v1/users/:uid", "allow:Permission('users.view')")

// Prepare user's permission info
_principal := &principal{
    permissions: []string{"users.view"},
}

// Perform match check
endpoint := "GET /api/v1/users/123"
checked, err := patrol.Check(endpoint, _principal)
if err !=nil {
    // No matched route, can ignore/pass
    log.Println(err)
}

fmt.Logf("check: %v", checked) // true
```

Initialize `Patrol` instance with config:

```go
// Load from config file
rulePath := "./rule.txt"
p, err := NewPatrol(WithConfig(rulePath))

// Configure principal's permissions
_principal := &principal{
    roles: []string{"admin"},
}

//
endpoint := "GET /api/v1/books?category=2"
checked, err := p.Check(endpoint, _principal)
if err !=nil {
    // No matched route, can ignore/pass
    log.Println(err)
}


fmt.Logf("check: %v", checked) // true
```

Rule file [rule.txt](file:///Users/einsitang/github/sevlow/go-security/rule.txt) format:

**endpoint**, **express**

```
# rule.txt
# Ignore method
/api/v1/books?category=:category, allow:Role('admin') and $category == '2'
# Allow only GET or POST
GET/POST /api/v1/files/:year/:month/:day/:filename, allow:Role('admin') and $year == '2025' and $month == '05'
```

---

## 🛠️ Integrations

- **gin-security** - gin middleware (under development)

## 💡 FAQ

## Contributing

Contributions are welcome! Please feel free to submit issues or PRs.