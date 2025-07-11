package security

import (
	"fmt"
	"testing"
)

// Test principal implementation for testing
type testPrincipal struct {
	id          string
	roles       []string
	permissions []string
	groups      []string
}

func (p *testPrincipal) Id() string {
	return p.id
}

func (p *testPrincipal) Roles() []string {
	return p.roles
}

func (p *testPrincipal) Permissions() []string {
	return p.permissions
}

func (p *testPrincipal) Groups() []string {
	return p.groups
}

func TestGuard_NewGuard(t *testing.T) {
	tests := []struct {
		name      string
		express   string
		wantError bool
	}{
		{
			name:      "Valid allow expression",
			express:   "allow: Role('admin')",
			wantError: false,
		},
		{
			name:      "Valid deny expression",
			express:   "deny: Permission('user.delete')",
			wantError: false,
		},
		{
			name:      "Complex expression",
			express:   "allow: Role('admin') or (Permission('user.read') and $category == 'public')",
			wantError: false,
		},
		{
			name:      "Invalid syntax - missing policy",
			express:   "Role('admin')",
			wantError: true,
		},
		{
			name:      "Invalid syntax - wrong operator",
			express:   "allow: Role('admin') & Permission('user.read')",
			wantError: true,
		},
		{
			name:      "Empty expression",
			express:   "",
			wantError: true,
		},
		{
			name:      "Invalid policy",
			express:   "invalid: Role('admin')",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard, err := NewGuard(tt.express)
			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error for expression: %s", tt.express)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for expression %s: %v", tt.express, err)
				}
				if guard == nil {
					t.Error("Expected guard instance, got nil")
				}
				if guard.Express() != tt.express {
					t.Errorf("Expected expression %s, got %s", tt.express, guard.Express())
				}
			}
		})
	}
}

func TestGuard_RoleCheck(t *testing.T) {
	tests := []struct {
		name      string
		express   string
		principal *testPrincipal
		params    map[string]any
		expected  bool
		wantError bool
	}{
		{
			name:    "Single role check - success",
			express: "allow: Role('admin')",
			principal: &testPrincipal{
				roles: []string{"admin", "user"},
			},
			expected: true,
		},
		{
			name:    "Single role check - fail",
			express: "allow: Role('admin')",
			principal: &testPrincipal{
				roles: []string{"user", "guest"},
			},
			expected: false,
		},
		{
			name:    "Multiple roles check - success",
			express: "allow: Roles('admin', 'manager')",
			principal: &testPrincipal{
				roles: []string{"manager"},
			},
			expected: true,
		},
		{
			name:    "Multiple roles check - fail",
			express: "allow: Roles('admin', 'manager')",
			principal: &testPrincipal{
				roles: []string{"user", "guest"},
			},
			expected: false,
		},
		{
			name:    "Deny policy with role",
			express: "deny: Role('guest')",
			principal: &testPrincipal{
				roles: []string{"guest"},
			},
			expected: false,
		},
		{
			name:    "Deny policy with role - not matching",
			express: "deny: Role('guest')",
			principal: &testPrincipal{
				roles: []string{"admin"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard, err := NewGuard(tt.express)
			if err != nil {
				t.Fatalf("Failed to create guard: %v", err)
			}

			result, err := guard.Check(&SecurityContext{
				Principal: tt.principal,
				Params:    tt.params,
			})

			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}

func TestGuard_PermissionCheck(t *testing.T) {
	tests := []struct {
		name      string
		express   string
		principal *testPrincipal
		expected  bool
	}{
		{
			name:    "Single permission check - success",
			express: "allow: Permission('user.read')",
			principal: &testPrincipal{
				permissions: []string{"user.read", "user.write"},
			},
			expected: true,
		},
		{
			name:    "Single permission check - fail",
			express: "allow: Permission('user.delete')",
			principal: &testPrincipal{
				permissions: []string{"user.read", "user.write"},
			},
			expected: false,
		},
		{
			name:    "Multiple permissions check - success",
			express: "allow: Permissions('user.read', 'user.write')",
			principal: &testPrincipal{
				permissions: []string{"user.write"},
			},
			expected: true,
		},
		{
			name:    "Multiple permissions check - fail",
			express: "allow: Permissions('user.delete', 'admin.all')",
			principal: &testPrincipal{
				permissions: []string{"user.read", "user.write"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard, err := NewGuard(tt.express)
			if err != nil {
				t.Fatalf("Failed to create guard: %v", err)
			}

			result, err := guard.Check(&SecurityContext{
				Principal: tt.principal,
			})

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGuard_GroupCheck(t *testing.T) {
	tests := []struct {
		name      string
		express   string
		principal *testPrincipal
		expected  bool
	}{
		{
			name:    "Single group check - success",
			express: "allow: Group('developers')",
			principal: &testPrincipal{
				groups: []string{"developers", "testers"},
			},
			expected: true,
		},
		{
			name:    "Single group check - fail",
			express: "allow: Group('admins')",
			principal: &testPrincipal{
				groups: []string{"developers", "testers"},
			},
			expected: false,
		},
		{
			name:    "Multiple groups check - success",
			express: "allow: Groups('admins', 'managers')",
			principal: &testPrincipal{
				groups: []string{"managers"},
			},
			expected: true,
		},
		{
			name:    "Multiple groups check - fail",
			express: "allow: Groups('admins', 'managers')",
			principal: &testPrincipal{
				groups: []string{"developers", "testers"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard, err := NewGuard(tt.express)
			if err != nil {
				t.Fatalf("Failed to create guard: %v", err)
			}

			result, err := guard.Check(&SecurityContext{
				Principal: tt.principal,
			})

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGuard_ParameterCheck(t *testing.T) {
	tests := []struct {
		name      string
		express   string
		principal *testPrincipal
		params    map[string]any
		custom    map[string]string
		expected  bool
	}{
		{
			name:    "String parameter comparison - success",
			express: "allow: $category == 'public'",
			params: map[string]any{
				"category": "public",
			},
			expected: true,
		},
		{
			name:    "String parameter comparison - fail",
			express: "allow: $category == 'private'",
			params: map[string]any{
				"category": "public",
			},
			expected: false,
		},
		{
			name:    "Integer parameter comparison - success",
			express: "allow: $age >= 18",
			params: map[string]any{
				"age": 25,
			},
			expected: true,
		},
		{
			name:    "Integer parameter comparison - fail",
			express: "allow: $age >= 18",
			params: map[string]any{
				"age": 16,
			},
			expected: false,
		},
		{
			name:    "Custom parameter check - success",
			express: "allow: #env == 'development'",
			custom: map[string]string{
				"env": "development",
			},
			expected: true,
		},
		{
			name:    "Combined parameter and role check",
			express: "allow: Role('admin') and $action == 'delete'",
			principal: &testPrincipal{
				roles: []string{"admin"},
			},
			params: map[string]any{
				"action": "delete",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard, err := NewGuard(tt.express)
			if err != nil {
				t.Fatalf("Failed to create guard: %v", err)
			}

			result, err := guard.Check(&SecurityContext{
				Principal:    tt.principal,
				Params:       tt.params,
				CustomParams: tt.custom,
			})

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGuard_LogicalOperators(t *testing.T) {
	tests := []struct {
		name      string
		express   string
		principal *testPrincipal
		params    map[string]any
		expected  bool
	}{
		{
			name:    "AND operator - both true",
			express: "allow: Role('admin') and Permission('user.read')",
			principal: &testPrincipal{
				roles:       []string{"admin"},
				permissions: []string{"user.read"},
			},
			expected: true,
		},
		{
			name:    "AND operator - first false",
			express: "allow: Role('admin') and Permission('user.read')",
			principal: &testPrincipal{
				roles:       []string{"user"},
				permissions: []string{"user.read"},
			},
			expected: false,
		},
		{
			name:    "OR operator - first true",
			express: "allow: Role('admin') or Permission('user.read')",
			principal: &testPrincipal{
				roles:       []string{"admin"},
				permissions: []string{},
			},
			expected: true,
		},
		{
			name:    "OR operator - second true",
			express: "allow: Role('admin') or Permission('user.read')",
			principal: &testPrincipal{
				roles:       []string{"user"},
				permissions: []string{"user.read"},
			},
			expected: true,
		},
		{
			name:    "OR operator - both false",
			express: "allow: Role('admin') or Permission('user.read')",
			principal: &testPrincipal{
				roles:       []string{"user"},
				permissions: []string{"user.write"},
			},
			expected: false,
		},
		{
			name:    "NOT operator - true",
			express: "allow: !Role('guest')",
			principal: &testPrincipal{
				roles: []string{"admin"},
			},
			expected: true,
		},
		{
			name:    "NOT operator - false",
			express: "allow: !Role('guest')",
			principal: &testPrincipal{
				roles: []string{"guest"},
			},
			expected: false,
		},
		{
			name:    "Complex expression with parentheses",
			express: "allow: Role('admin') or (Permission('user.read') and $category == 'public')",
			principal: &testPrincipal{
				roles:       []string{"user"},
				permissions: []string{"user.read"},
			},
			params: map[string]any{
				"category": "public",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard, err := NewGuard(tt.express)
			if err != nil {
				t.Fatalf("Failed to create guard: %v", err)
			}

			result, err := guard.Check(&SecurityContext{
				Principal: tt.principal,
				Params:    tt.params,
			})

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGuard_MathematicalOperations(t *testing.T) {
	tests := []struct {
		name     string
		express  string
		params   map[string]any
		expected bool
	}{
		{
			name:    "Addition operation",
			express: "allow: $age + 5 >= 25",
			params: map[string]any{
				"age": 20,
			},
			expected: true,
		},
		{
			name:    "Subtraction operation",
			express: "allow: $total - $used <= 100",
			params: map[string]any{
				"total": 150,
				"used":  40,
			},
			expected: false,
		},
		{
			name:    "Multiplication operation",
			express: "allow: $price * $quantity <= 1000",
			params: map[string]any{
				"price":    50,
				"quantity": 15,
			},
			expected: true,
		},
		{
			name:    "Division operation",
			express: "allow: $total / $count >= 10",
			params: map[string]any{
				"total": 100,
				"count": 5,
			},
			expected: true,
		},
		{
			name:    "Modulo operation",
			express: "allow: $number % 2 == 0",
			params: map[string]any{
				"number": 10,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard, err := NewGuard(tt.express)
			if err != nil {
				t.Fatalf("Failed to create guard: %v", err)
			}

			result, err := guard.Check(&SecurityContext{
				Params: tt.params,
			})

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGuard_ComparisonOperators(t *testing.T) {
	tests := []struct {
		name     string
		express  string
		params   map[string]any
		expected bool
	}{
		{
			name:    "Equal operator - true",
			express: "allow: $status == 'active'",
			params: map[string]any{
				"status": "active",
			},
			expected: true,
		},
		{
			name:    "Not equal operator - true",
			express: "allow: $status != 'inactive'",
			params: map[string]any{
				"status": "active",
			},
			expected: true,
		},
		{
			name:    "Greater than operator - true",
			express: "allow: $score > 80",
			params: map[string]any{
				"score": 85,
			},
			expected: true,
		},
		{
			name:    "Greater than or equal operator - true",
			express: "allow: $score >= 80",
			params: map[string]any{
				"score": 80,
			},
			expected: true,
		},
		{
			name:    "Less than operator - true",
			express: "allow: $age < 18",
			params: map[string]any{
				"age": 16,
			},
			expected: true,
		},
		{
			name:    "Less than or equal operator - true",
			express: "allow: $age <= 18",
			params: map[string]any{
				"age": 18,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard, err := NewGuard(tt.express)
			if err != nil {
				t.Fatalf("Failed to create guard: %v", err)
			}

			result, err := guard.Check(&SecurityContext{
				Params: tt.params,
			})

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGuard_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		express   string
		principal *testPrincipal
		params    map[string]any
		custom    map[string]string
		expected  bool
		wantError bool
	}{
		{
			name:    "Empty roles array",
			express: "allow: Role('admin')",
			principal: &testPrincipal{
				roles: []string{},
			},
			expected: false,
		},
		{
			name:      "Nil principal",
			express:   "allow: Role('admin')",
			principal: nil,
			wantError: true,
		},
		{
			name:     "Missing parameter",
			express:  "allow: $nonexistent == 'value'",
			params:   map[string]any{},
			expected: false,
		},
		{
			name:    "Type mismatch in comparison",
			express: "allow: $stringParam > 10",
			params: map[string]any{
				"stringParam": "hello",
			},
			wantError: true,
		},
		{
			name:     "Always true expression",
			express:  "allow: 1 == 1",
			expected: true,
		},
		{
			name:     "Always false expression",
			express:  "allow: 1 == 2",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard, err := NewGuard(tt.express)
			if err != nil {
				if !tt.wantError {
					t.Fatalf("Failed to create guard: %v", err)
				}
				return
			}

			var result bool
			var checkErr error

			// Handle potential panic from nil principal
			func() {
				defer func() {
					if r := recover(); r != nil {
						checkErr = fmt.Errorf("panic occurred: %v", r)
					}
				}()
				result, checkErr = guard.Check(&SecurityContext{
					Principal:    tt.principal,
					Params:       tt.params,
					CustomParams: tt.custom,
				})
			}()

			if tt.wantError {
				if checkErr == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if checkErr != nil {
					t.Errorf("Unexpected error: %v", checkErr)
				}
				if result != tt.expected {
					t.Errorf("Expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}

func BenchmarkGuard_SimpleRoleCheck(b *testing.B) {
	guard, err := NewGuard("allow: Role('admin')")
	if err != nil {
		b.Fatalf("Failed to create guard: %v", err)
	}

	principal := &testPrincipal{
		roles: []string{"admin", "user"},
	}

	context := &SecurityContext{
		Principal: principal,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := guard.Check(context)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkGuard_ComplexExpression(b *testing.B) {
	guard, err := NewGuard("allow: (Role('admin') or Role('manager')) and Permission('user.read') and $age >= 18")
	if err != nil {
		b.Fatalf("Failed to create guard: %v", err)
	}

	principal := &testPrincipal{
		roles:       []string{"admin"},
		permissions: []string{"user.read", "user.write"},
	}

	context := &SecurityContext{
		Principal: principal,
		Params: map[string]any{
			"age": 25,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := guard.Check(context)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkGuard_MathematicalOperations(b *testing.B) {
	guard, err := NewGuard("allow: $price * $quantity + $tax <= $budget and $discount >= 0")
	if err != nil {
		b.Fatalf("Failed to create guard: %v", err)
	}

	context := &SecurityContext{
		Params: map[string]any{
			"price":    50,
			"quantity": 10,
			"tax":      45,
			"budget":   600,
			"discount": 5,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := guard.Check(context)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}
