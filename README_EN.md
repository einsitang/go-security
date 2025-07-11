# go-security

[![Go report](https://goreportcard.com/badge/github.com/einsitang/go-security)](https://goreportcard.com/report/github.com/einsitang/go-security)
[![License](https://img.shields.io/github/license/einsitang/go-security)](./LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/einsitang/go-security)](https://golang.org/doc/devel/release.html)

<div align="center">
  <strong>English | <a href="README.md">中文</a></strong>
</div>

go-security is a lightweight and flexible security framework designed specifically for Go applications, aiming to provide fine-grained access control based on endpoint routing and permission expressions.

## 🚀 Overview

Developers can define security access rules for endpoints through concise syntax. It supports **dynamic route parameters**, **wildcard paths**, and combining **roles**, **permissions**, and **groups** to write easy-to-understand **logical expression** components.

## ✨ Features

- 🔒 **Flexible Permission Control** - Supports fine-grained access control based on roles, permissions, and groups
- 🛣️ **Dynamic Route Matching** - Supports path parameters, query parameters, and wildcard paths
- 📝 **Expression Syntax** - Concise and intuitive permission expression syntax
- ⚡ **High Performance** - Lightweight design with compile-time syntax analysis
- 🔧 **Easy Integration** - Simple API design, easy to integrate with existing projects
- 📋 **Configuration File Support** - Supports batch definition of permission rules through configuration files

## 📦 Installation

```bash
go get github.com/einsitang/go-security
```
> go-security now is not release yet

## 🎯 Quick Start

### 1. Define User Principal (SecurityPrincipal)

```go
package main

import "github.com/einsitang/go-security"

// Implement SecurityPrincipal interface
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

### 2. Using Guard

`guard` is the most basic expression application unit. When initializing a guard, the expression is simultaneously parsed into an abstract syntax tree.

When using guard, you don't need to consider endpoints ("endpoint routing").

```go
func main() {
    // Create permission checker
    guard, err := security.NewGuard("allow: Role('admin') and $type == 'user'")
    if err != nil {
        panic(err)
    }

    // Create user
    user := &User{
        id:    "123",
        roles: []string{"admin"},
    }

    // Perform permission check
    passed, err := guard.Check(&security.SecurityContext{
        Principal: (*security.SecurityPrincipal)(user),
        Params: map[string]any{
            "type": "user",
        },
    })

    if err != nil {
        panic(err)
    }

    fmt.Printf("Permission check result: %v\n", passed) // Output: Permission check result: true
}
```

### 3. Using Sentinel

`sentinel` can define the relationship between endpoints and expressions, forming an endpoint-based routing table for quick matching. Use `sentinel` when you don't have routing components or need to uniformly define route authentication policies.

```go
func main() {
    // Create sentinel
    sentinel, err := security.NewSentinel()
    if err != nil {
        panic(err)
    }

    // Add endpoint rules
    err = sentinel.AddEndpoint("GET /api/v1/users/:userId", "allow: Permission('users.view')")
    if err != nil {
        panic(err)
    }

    err = sentinel.AddEndpoint("/api/v1/orders?category=:category", "allow: Permission('orders.view') or $category == 'public'")
    if err != nil {
        panic(err)
    }

    // Create user
    user := &User{
        id:          "123",
        permissions: []string{"users.view"},
    }

    // Check permissions
    endpoint := "GET /api/v1/users/456"
    passed, err := sentinel.Check(endpoint, (*security.SecurityPrincipal)(user), nil)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Access %s permission check: %v\n", endpoint, passed)
}
```

## 📚 Detailed Documentation

### Endpoint Route Format

Endpoint format: `METHOD PATH`

#### Basic Format

```
GET /api/v1/users           # Specify GET method
POST /api/v1/users          # Specify POST method
GET/POST /api/v1/users      # Support multiple methods, separated by /
/api/v1/users               # Ignore method, match all HTTP methods
```

#### Path Parameters

```
GET /api/v1/users/:userId                    # Path parameter $userId
GET /api/v1/posts/:postId/comments/:id       # Multiple path parameters
```

Example: `GET /api/v1/users/123` matches pattern `GET /api/v1/users/:userId`, parameter `$userId = "123"`

#### Query Parameters

```
GET /api/v1/books?category=:category         # Query parameter $category
GET /api/v1/search?q=:query&type=:type       # Multiple query parameters
```

Example: `GET /api/v1/books?category=fiction` matches pattern `GET /api/v1/books?category=:category`, parameter `$category = "fiction"`

#### Wildcards

```
/api/v1/files/*             # Wildcard $0, matches all remaining paths
```

Example: `/api/v1/files/2023/05/report.pdf` matches pattern `/api/v1/files/*`, parameter `$0 = "2023/05/report.pdf"`

> ⚠️ **Note**: Wildcards can only be used at the end of paths

### Permission Expression Syntax

#### Policy Types

- `allow` - Allow policy, allows access when expression is true
- `deny` - Deny policy, denies access when expression is true

#### Built-in Functions

| Function | Description | Example |
|----------|-------------|---------|
| `Role(role)` | Check single role | `Role('admin')` |
| `Roles(role1, role2, ...)` | Check multiple roles (OR relationship) | `Roles('admin', 'manager')` |
| `Permission(perm)` | Check single permission | `Permission('users.read')` |
| `Permissions(perm1, perm2, ...)` | Check multiple permissions (OR relationship) | `Permissions('users.read', 'users.write')` |
| `Group(group)` | Check single group | `Group('developers')` |
| `Groups(group1, group2, ...)` | Check multiple groups (OR relationship) | `Groups('developers', 'admins')` |

#### Operators

| Type | Operators | Description |
|------|-----------|-------------|
| Logical | `and`, `or` | Logical AND, logical OR |
| Comparison | `==`, `!=`, `>`, `>=`, `<`, `<=` | Equal, not equal, greater than, greater than or equal, less than, less than or equal |
| Mathematical | `+`, `-`, `*`, `/`, `%` | Add, subtract, multiply, divide, modulo |
| Unary | `!` | Logical NOT |

#### Expression Examples

```bash
# Basic role check
allow: Role('admin')

# Multi-condition combination
allow: Role('admin') or (Permission('users.read') and $category == 'public')

# Parameter validation
allow: Role('manager') and $userId == 'self'

# Complex logic
deny: Group('guest') and $action == 'delete'

# Numerical calculation
allow: Permission('quota.check') and $requested <= $available * 0.8
```

### Using Configuration Files

#### Create Configuration File (rule.txt)

```
# This is a comment line, lines starting with # will be ignored
# Format: endpoint, expression

# User management APIs
GET /api/v1/users, allow: Permission('users.list')
GET /api/v1/users/:userId, allow: Permission('users.view') or $userId == 'self'
POST /api/v1/users, allow: Role('admin')
PUT /api/v1/users/:userId, allow: Role('admin') or $userId == 'self'

# File management APIs
GET/POST /api/v1/files/*, allow: Role('admin') and $0 != 'secret'

# Conditional query APIs
/api/v1/books?category=:category, allow: Permission('books.read') or $category == 'public'
```

#### Initialize with Configuration File

```go
sentinel, err := security.NewSentinel(
    security.WithConfig("./rule.txt"),
)
if err != nil {
    panic(err)
}

// Use directly, rules are loaded from configuration file
user := &User{permissions: []string{"users.view"}}
passed, err := sentinel.Check("GET /api/v1/users/123", (*security.SecurityPrincipal)(user), nil)
```

### Custom Parameters

In addition to path parameters and query parameters, you can pass custom parameters for expression computation:

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

Using custom parameters in expressions:

```
allow: Permission('documents.read') and #action == 'read' and #resource == 'document'
```

### Strict Matching vs Normal Matching

#### Normal Matching (Check)

Only matches HTTP method and path, ignoring strict matching of query parameters:

```go
// Rule: /api/books?category=:category
// Request: GET /api/books?category=fiction&page=1
// Result: ✅ Match successful, $category = "fiction"
passed, err := sentinel.Check(endpoint, user, nil)
```

#### Strict Matching (StrictCheck)

Matches HTTP method, path, and query parameters simultaneously:

```go
// Rule: /api/books?category=:category
// Request: GET /api/books?category=fiction&page=1
// Result: ❌ Match failed, because there's an extra page parameter
passed, err := sentinel.StrictCheck(endpoint, user, nil)

// Request: GET /api/books?category=fiction
// Result: ✅ Match successful
```

## 🔧 API Reference

### Guard Interface

```go
type Guard interface {
    // Return original expression
    Express() string
    
    // Permission check
    // Return values: pass(true)/fail(false), error information
    Check(context *SecurityContext) (bool, error)
}

// Create new Guard instance
func NewGuard(express string) (Guard, error)
```

### Sentinel Interface

```go
type Sentinel interface {
    // Add endpoint rule
    AddEndpoint(pattern string, express string) error
    
    // Normal permission check (not strictly matching query parameters)
    Check(endpoint string, principal SecurityPrincipal, customParams map[string]string) (bool, error)
    
    // Strict permission check (strictly matching query parameters)
    StrictCheck(endpoint string, principal SecurityPrincipal, customParams map[string]string) (bool, error)
    
    // Clear all endpoint rules
    CleanEndpoints()
}

// Create new Sentinel instance
func NewSentinel(options ...SentinelOption) (Sentinel, error)

// Configuration options
func WithConfig(configPath string) SentinelOption
```

### SecurityPrincipal Interface

```go
type SecurityPrincipal interface {
    Id() string
    Roles() []string
    Permissions() []string
    Groups() []string
}
```

### SecurityContext Structure

```go
type SecurityContext struct {
    Params       map[string]any    // Path and query parameters
    Principal    SecurityPrincipal // User principal information
    CustomParams map[string]string // Custom parameters
}
```

## 🛠️ Integration Examples

### Integration with Gin Framework

```go
func AuthMiddleware(sentinel security.Sentinel) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Construct endpoint string
        endpoint := c.Request.Method + " " + c.Request.URL.Path
        if c.Request.URL.RawQuery != "" {
            endpoint += "?" + c.Request.URL.RawQuery
        }
        
        // Get user information from context
        user, exists := c.Get("user")
        if !exists {
            c.JSON(401, gin.H{"error": "Unauthenticated"})
            c.Abort()
            return
        }
        
        // Permission check
        passed, err := sentinel.Check(endpoint, user.(security.SecurityPrincipal), nil)
        if err != nil {
            c.JSON(500, gin.H{"error": "Permission check failed"})
            c.Abort()
            return
        }
        
        if !passed {
            c.JSON(403, gin.H{"error": "Insufficient permissions"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}

// Use middleware
func main() {
    sentinel, _ := security.NewSentinel(security.WithConfig("./rules.txt"))
    
    r := gin.Default()
    r.Use(AuthMiddleware(sentinel))
    
    r.GET("/api/v1/users/:id", getUserHandler)
    r.POST("/api/v1/users", createUserHandler)
    
    r.Run(":8080")
}
```

## 🧪 Testing

Run tests:

```bash
go test ./...
```

Run benchmark tests:

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

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork this repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 💡 FAQ

### Q: How to handle complex permission logic?

A: You can implement complex logic by combining multiple expressions or using custom parameters. For example:

```
allow: (Role('admin') or Role('manager')) and (#department == $userDepartment) and $action != 'delete'
```

### Q: How is the performance?

A: go-security compiles expressions into AST during initialization and directly executes the compiled syntax tree at runtime, providing excellent performance.

### Q: Does it support dynamic permission updates?

A: Yes. You can call `CleanEndpoints()` to clear existing rules and then re-add rules, or create a new Sentinel instance.

### Q: How to debug permission expressions?

A: You can use the expression parser's debugging functionality, or check parameter values and expression execution results through log output.

## 📖 More Examples

Check the [examples](examples/) directory for more usage examples.
