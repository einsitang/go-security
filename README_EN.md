# go-security

[![Go report](https://goreportcard.com/badge/github.com/einsitang/go-security)](https://goreportcard.com/report/github.com/einsitang/go-security)
[![License](https://img.shields.io/github/license/einsitang/go-security)](./LICENSE)

go-security is a lightweight and flexible security framework designed specifically for Go applications, aiming to provide fine-grained access control based on endpoint routing and permission expressions.

## 🚀 Overview

Developers can define secure access rules for endpoints using concise syntax. It supports **dynamic route parameters**, **wildcard paths**, and combining **roles**, **permissions**, and **groups** into easy-to-understand **logical expressions**.

### Endpoint Routing

`endpoint` format:

**METHOD** **PATH**

Example:

`GET /api/v1/users` — **method** is case-insensitive; uppercase is recommended.

Multiple **methods** can be separated by [/](file:///Users/einsitang/github/sevlow/go-security/README.md).

`GET/POST /api/v1/users`

You can also omit the **method** entirely:

`/api/v1/users` — This matches all **methods** when matching.

`/api/v1/users` will match both `GET /api/v1/users` and `POST /api/v1/users`.

#### Parameters

`GET /api/v1/users/:userId` // $userId

Example: `GET /api/v1/users/1`, $userId = 1

`GET /api/v1/books?category=:category` // $category

Example: `GET /api/v1/books?category=computer`, $category = computer

#### Wildcards

`/api/v1/action/*` // $0

Example: `/api/v1/action/delete`, $0 = delete

> Wildcards can only be used at the end of a path to avoid matching multiple segments.
> Example:
> `/imgs/*/:year/:month/:day/:fileName`
> 
> `/imgs/avator/2025/05/19/xxx.jpg`, $0 = avator/2025/05/19/xxx.jpg

## Permission Expression

### Policy

`allow` / `deny`

### Role(s)/ Permission(s) / Group(s)

`Role('admin')`

`Roles('admin','manager')`
> Equivalent to: Role('admin') or Role('manager')

`Permission('doc:read')`

`Permissions('doc:read','doc:list')`
> Equivalent to: Permission('doc:read') or Permission('doc:list')

`Group("engineer")`

`Groups('enginner','manager')`
> Equivalent to: Group('enginner') or Group('manager')

### Expressions

- Supports built-in functions: `Role`, `Permission`, `Group` , `Roles` , `Permissions` , `Groups`
- Supports logical operators: `and`, `or`
- Supports comparison operators: `==`, `!=`, `>`, `>=`, `<`, `<=`
- Supports arithmetic operators: `+`, `-`, `*`, `%`
- Support the unit operator `!`

```shell
# example:
allow: Role('admin') or (Permission('doc:read') and $category == 'guest')
allow: Roles('admin','manager') or Permissions('doc:read','doc:list')
deny: Group('guest') and $category == 'tech'
```

## Usage

### SecurityPrincipal

Create and implement the `SecurityPrincipal` interface to specify permission (Roles/Permissions/Groups) information. You can restore this information via file reading, database, distributed cache, memory, etc.

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

### Guard

Guard is the simplest concept in go-security. You can create a guard using an **expression**, and when permission checks are needed, directly call the [Guard.Check(SecurityContext)](https://github.com/einsitang/go-security/guard.go) method to determine whether access should be granted (`allow`).

```go
guard,err := NewGuard("allow:Role('admin') and $type == 'user'")
if err != nil {
    // There was an error in the expression
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

You can place the Guard before any code logic that requires a permission check.

### Sentinel

You can dynamically add endpoints to organize routes, then use Sentinel to automatically assign different guards to different endpoints.

```go
sentinel, err := NewSentinel()
if err!=nil {
    ....
    return
}
// Add endpoint
sentinel.AddEndpoint("/api/v1/users/:uid", "allow:Permission('users.view')")
sentinel.AddEndpoint("/api/v1/orders?category=:category", "allow:Permission('users.view') or $category=='book'")

// Organize permission info for the user needing the check
_principal := &principal{
    permissions: []string{"users.view"},
}

// Matching check
endpoint:="GET /api/v1/users/123"
checked, err := sentinel.Check(endpoint, _principal)
if err !=nil {
    // show error
    log.Println(err)
} else {
    fmt.Logf("check: %v",checked) // true
}
```

Initialize the Sentinel instance with `WithConfig`:

```go
// Using config file
rulePath := "./rule.txt"
sentinel, err := NewSentinel(WithConfig(rulePath))

// Configure principal's permissions
_principal := &principal{
    roles: []string{"admin"},
}

//
endpoint := "GET /api/v1/books?category=2"
checked, err := sentinel.Check(endpoint, _principal)
if err !=nil {
    // show error
    log.Println(err)
} else {
    fmt.Logf("check: %v",checked) // true
}
```

Rule file `rule.txt` format:

**endpoint**, **express**

```
# rule.txt
# Ignore method
/api/v1/books?category=:category, allow:Role('admin') and $category == '2'
# Only support GET or POST methods
GET/POST /api/v1/files/:year/:month/:day/:filename, allow:Role('admin') and $year == '2025' and $month == '05'
```

#### Strict Match Check - StrictCheck

p.StrictCheck(endpoint, _principal)

`/api/v1/orders?category=:category` strictly matches query parameters (* /api/v1/orders?category=:category)

p.Check(endpoint, _principal)

`/api/v1/orders?category=:category` only matches method and path (* /api/v1/orders)

> Strict matching only affects route matching, not parameter extraction after matching.

## 🛠️ Integration

gin-security - gin middleware (in development)

## 💡 FAQ

## Contributing

