# Refinement of the README.md Introduction

## Endpoint Routing (endpoint)

### Parameters
- Format: `/api/v1/users/:userId` // $userId
- Example: `/api/v1/users/1` , `$userId = 1`
- Query parameters: `/api/v1/books?category=:category` // $category
- Example: `/api/v1/books?category=computer` , `$category = computer`

### Wildcards
- Format: `/api/v1/action/*` // $0
- Example: `/api/v1/action/delete` , `$0 = delete`
> **Note:** Wildcards can only be used at the end of a path to avoid matching multiple paths.
> Example:
> `/imgs/*/:year/:month/:day/:fileName`
>
> `/imgs/avator/2025/05/19/xxx.jpg` , `$0 = avator/2025/05/19/xxx.jpg`

## Permission Expression (express)

### Policies
- `allow`
- `deny`

### Roles, Permissions, and Groups
- Role: `Role("admin")`
- Permission: `Permission('doc:read')`
- Group: `Group("engineer")`

### Expressions
- Supports built-in functions: `Role`, `Permission`, `Group`
- Logical operators: `and`, `or`
- Comparison operators: `==`, `!=`, `>`, `>=`, `<`, `<=`
- Mathematical operators: `+`, `-`, [*](file:///Users/einsitang/github/sevlow/go-security/README.md), [/](file:///Users/einsitang/github/sevlow/go-security/README.md), `%`

#### Examples:
``` 
# example:
allow: Role("admin") or (Permission('doc:read') and $category == "guest")
deny: Group("guest") and $category == "tech"
```

## Usage

### Implementing the Principal Interface
Create and implement the [Principal](file:///Users/einsitang/github/sevlow/go-security/internal/expr/ctx/context.go#L2-L7) interface to specify user permissions (Roles, Permissions, Groups):

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

### Creating a Security Instance with Rule Files
Load rules from a file to create a `Security` instance.

#### Rule File `rule.txt` Format
Format: `endpoint,express`

```
# rule.txt
/api/v1/books?category=:category, allow:Role('admin') and $category == '2'
/api/v1/files/:year/:month/:day/:filename, allow:Role('admin') and $year == '2025' and $month == '05'
```

### Initializing the Security Instance with Configuration
Use `WithConfig` to initialize the `Security` instance:

```go
// Through configuration file
rulePath := "./rule.txt"
security := NewSecurity(WithConfig(rulePath))

// Configure principal's permission information
_principal := &principal{
    roles: []string{"admin"},
}
endPoint := "/api/v1/books?category=2"
pass, err := security.Guard(endPoint, _principal)
if err != nil {
    // No route matched, error handling
    log.Println(err)
}
if pass {
    log.Println("Allow")
} else {
    log.Println("Block")
}
```

### Adding Endpoints and Expressions Dynamically
You can also dynamically register endpoints and expressions:

```go
security := NewSecurity()
security.RegEndpoint("/api/v1/books?category=:category", "allow:Role('admin') and $category == '2'")

// Configure principal's permission information
_principal := &principal{
    roles: []string{"admin"},
}

endPoint := "/api/v1/books?category=2"
pass, err := security.Guard(endPoint, _principal)
if err != nil {
    // No route matched, error handling
    log.Println(err)
}
if pass {
    log.Println("Allow")
} else {
    log.Println("Block")
}
```

### Integration with Gin Framework
For integration with the Gin framework, use `gin-security`.

### FAQ
Common questions and answers section.

### Contribution
Guidelines for contributing to the project.