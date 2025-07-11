package security

import (
	"fmt"
	"os"
	"testing"
)

// Test principal implementation for Sentinel tests
type sentinelTestPrincipal struct {
	id          string
	roles       []string
	permissions []string
	groups      []string
}

func (p *sentinelTestPrincipal) Id() string {
	return p.id
}

func (p *sentinelTestPrincipal) Roles() []string {
	return p.roles
}

func (p *sentinelTestPrincipal) Permissions() []string {
	return p.permissions
}

func (p *sentinelTestPrincipal) Groups() []string {
	return p.groups
}

func TestSentinel_NewSentinel(t *testing.T) {
	tests := []struct {
		name      string
		options   []SentinelOption
		wantError bool
	}{
		{
			name:      "Create sentinel without options",
			options:   nil,
			wantError: false,
		},
		{
			name:      "Create sentinel with empty options",
			options:   []SentinelOption{},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel, err := NewSentinel(tt.options...)
			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if sentinel == nil {
					t.Error("Expected sentinel instance, got nil")
				}
			}
		})
	}
}

func TestSentinel_AddEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		express   string
		wantError bool
	}{
		{
			name:      "Simple endpoint with GET method",
			endpoint:  "GET /api/users",
			express:   "allow: Role('admin')",
			wantError: false,
		},
		{
			name:      "Endpoint with path parameter",
			endpoint:  "GET /api/users/:id",
			express:   "allow: Permission('user.read')",
			wantError: false,
		},
		{
			name:      "Endpoint with query parameter",
			endpoint:  "GET /api/books?category=:category",
			express:   "allow: $category == 'public'",
			wantError: false,
		},
		{
			name:      "Endpoint with wildcard",
			endpoint:  "GET /api/files/*",
			express:   "allow: Role('admin')",
			wantError: false,
		},
		{
			name:      "Multiple methods",
			endpoint:  "GET/POST /api/users",
			express:   "allow: Role('admin')",
			wantError: false,
		},
		{
			name:      "No method specified",
			endpoint:  "/api/users",
			express:   "allow: Role('admin')",
			wantError: false,
		},
		{
			name:      "Invalid expression",
			endpoint:  "GET /api/users",
			express:   "invalid expression",
			wantError: true,
		},
		{
			name:      "Duplicate endpoint",
			endpoint:  "GET /api/users",
			express:   "allow: Role('user')",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel, err := NewSentinel()
			if err != nil {
				t.Fatalf("Failed to create sentinel: %v", err)
			}

			// Add the first endpoint for duplicate test
			if tt.name == "Duplicate endpoint" {
				err = sentinel.AddEndpoint("GET /api/users", "allow: Role('admin')")
				if err != nil {
					t.Fatalf("Failed to add initial endpoint: %v", err)
				}
			}

			err = sentinel.AddEndpoint(tt.endpoint, tt.express)
			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSentinel_Check_BasicRouting(t *testing.T) {
	tests := []struct {
		name      string
		endpoints map[string]string
		testCases []struct {
			endpoint  string
			expected  bool
			wantError bool
		}
		principal *sentinelTestPrincipal
		custom    map[string]string
	}{
		{
			name: "Simple role-based routing",
			endpoints: map[string]string{
				"GET /api/users":    "allow: Role('admin')",
				"POST /api/users":   "allow: Role('admin')",
				"DELETE /api/users": "deny: Role('guest')",
			},
			testCases: []struct {
				endpoint  string
				expected  bool
				wantError bool
			}{
				{"GET /api/users", true, false},
				{"POST /api/users", true, false},
				{"DELETE /api/users", true, false}, // deny: Role('guest') -> not guest, so allow
				{"PUT /api/users", false, true},    // No rule, should fail with error
			},
			principal: &sentinelTestPrincipal{
				roles: []string{"admin"},
			},
		},
		{
			name: "Permission-based routing",
			endpoints: map[string]string{
				"GET /api/documents":  "allow: Permission('doc.read')",
				"POST /api/documents": "allow: Permission('doc.create')",
			},
			testCases: []struct {
				endpoint  string
				expected  bool
				wantError bool
			}{
				{"GET /api/documents", true, false},
				{"POST /api/documents", false, false},
			},
			principal: &sentinelTestPrincipal{
				permissions: []string{"doc.read"},
			},
		},
		{
			name: "Multiple methods support",
			endpoints: map[string]string{
				"GET/POST /api/files": "allow: Role('user')",
			},
			testCases: []struct {
				endpoint  string
				expected  bool
				wantError bool
			}{
				{"GET /api/files", true, false},
				{"POST /api/files", true, false},
				{"PUT /api/files", false, true}, // No rule, should fail with error
			},
			principal: &sentinelTestPrincipal{
				roles: []string{"user"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel, err := NewSentinel()
			if err != nil {
				t.Fatalf("Failed to create sentinel: %v", err)
			}

			// Add endpoints
			for endpoint, express := range tt.endpoints {
				err = sentinel.AddEndpoint(endpoint, express)
				if err != nil {
					t.Fatalf("Failed to add endpoint %s: %v", endpoint, err)
				}
			}

			// Test cases
			for _, tc := range tt.testCases {
				result, err := sentinel.Check(tc.endpoint, tt.principal, tt.custom)
				if tc.wantError {
					if err == nil {
						t.Errorf("Expected error for endpoint %s but got none", tc.endpoint)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for endpoint %s: %v", tc.endpoint, err)
					}
					if result != tc.expected {
						t.Errorf("Endpoint %s: expected %v, got %v", tc.endpoint, tc.expected, result)
					}
				}
			}
		})
	}
}

func TestSentinel_Check_PathParameters(t *testing.T) {
	tests := []struct {
		name      string
		endpoints map[string]string
		testCases []struct {
			endpoint string
			expected bool
		}
		principal *sentinelTestPrincipal
	}{
		{
			name: "Single path parameter",
			endpoints: map[string]string{
				"GET /api/users/:id": "allow: Role('admin') or $id == 'self'",
			},
			testCases: []struct {
				endpoint string
				expected bool
			}{
				{"GET /api/users/123", true},  // admin role
				{"GET /api/users/self", true}, // id parameter match
			},
			principal: &sentinelTestPrincipal{
				roles: []string{"admin"},
			},
		},
		{
			name: "Multiple path parameters",
			endpoints: map[string]string{
				"GET /api/posts/:postId/comments/:commentId": "allow: Permission('comment.read') and $postId == '1'",
			},
			testCases: []struct {
				endpoint string
				expected bool
			}{
				{"GET /api/posts/1/comments/5", true},
				{"GET /api/posts/2/comments/5", false},
			},
			principal: &sentinelTestPrincipal{
				permissions: []string{"comment.read"},
			},
		},
		{
			name: "Wildcard parameter",
			endpoints: map[string]string{
				"GET /api/files/*": "allow: Role('admin')",
			},
			testCases: []struct {
				endpoint string
				expected bool
			}{
				{"GET /api/files/public/doc.pdf", true},
				{"GET /api/files/secret/config.yml", true},
				{"GET /api/files/user/data/file.txt", true},
			},
			principal: &sentinelTestPrincipal{
				roles: []string{"admin"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel, err := NewSentinel()
			if err != nil {
				t.Fatalf("Failed to create sentinel: %v", err)
			}

			// Add endpoints
			for endpoint, express := range tt.endpoints {
				err = sentinel.AddEndpoint(endpoint, express)
				if err != nil {
					t.Fatalf("Failed to add endpoint %s: %v", endpoint, err)
				}
			}

			// Test cases
			for _, tc := range tt.testCases {
				result, err := sentinel.Check(tc.endpoint, tt.principal, nil)
				if err != nil {
					t.Errorf("Unexpected error for endpoint %s: %v", tc.endpoint, err)
				}
				if result != tc.expected {
					t.Errorf("Endpoint %s: expected %v, got %v", tc.endpoint, tc.expected, result)
				}
			}
		})
	}
}

func TestSentinel_Check_QueryParameters(t *testing.T) {
	tests := []struct {
		name      string
		endpoints map[string]string
		testCases []struct {
			endpoint string
			expected bool
		}
		principal *sentinelTestPrincipal
	}{
		{
			name: "Single query parameter",
			endpoints: map[string]string{
				"GET /api/books?category=:category": "allow: Permission('book.read') or $category == 'public'",
			},
			testCases: []struct {
				endpoint string
				expected bool
			}{
				{"GET /api/books?category=fiction", true}, // permission
				{"GET /api/books?category=public", true},  // parameter match
				{"GET /api/books?category=private", true}, // has permission book.read
			},
			principal: &sentinelTestPrincipal{
				permissions: []string{"book.read"},
			},
		},
		{
			name: "Multiple query parameters",
			endpoints: map[string]string{
				"GET /api/search?q=:q&type=:type": "allow: $type == 'public' and $q != 'admin'",
			},
			testCases: []struct {
				endpoint string
				expected bool
			}{
				{"GET /api/search?q=golang&type=public", true},
				{"GET /api/search?q=admin&type=public", false}, // query is admin
				{"GET /api/search?q=golang&type=private", false},
			},
			principal: &sentinelTestPrincipal{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel, err := NewSentinel()
			if err != nil {
				t.Fatalf("Failed to create sentinel: %v", err)
			}

			// Add endpoints
			for endpoint, express := range tt.endpoints {
				err = sentinel.AddEndpoint(endpoint, express)
				if err != nil {
					t.Fatalf("Failed to add endpoint %s: %v", endpoint, err)
				}
			}

			// Test cases
			for _, tc := range tt.testCases {
				result, err := sentinel.Check(tc.endpoint, tt.principal, nil)
				if err != nil {
					t.Errorf("Unexpected error for endpoint %s: %v", tc.endpoint, err)
				}
				if result != tc.expected {
					t.Errorf("Endpoint %s: expected %v, got %v", tc.endpoint, tc.expected, result)
				}
			}
		})
	}
}

func TestSentinel_StrictCheck(t *testing.T) {
	tests := []struct {
		name      string
		endpoints map[string]string
		testCases []struct {
			endpoint     string
			expectNormal bool
			expectStrict bool
		}
		principal *sentinelTestPrincipal
	}{
		{
			name: "Query parameter strict matching",
			endpoints: map[string]string{
				"GET /api/books?category=:category": "allow: Role('user')",
			},
			testCases: []struct {
				endpoint     string
				expectNormal bool
				expectStrict bool
			}{
				{"GET /api/books?category=fiction", true, true},
				{"GET /api/books?category=fiction&page=1", true, true}, // Extra parameter allowed
			},
			principal: &sentinelTestPrincipal{
				roles: []string{"user"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel, err := NewSentinel()
			if err != nil {
				t.Fatalf("Failed to create sentinel: %v", err)
			}

			// Add endpoints
			for endpoint, express := range tt.endpoints {
				err = sentinel.AddEndpoint(endpoint, express)
				if err != nil {
					t.Fatalf("Failed to add endpoint %s: %v", endpoint, err)
				}
			}

			// Test cases
			for _, tc := range tt.testCases {
				// Normal check
				resultNormal, err := sentinel.Check(tc.endpoint, tt.principal, nil)
				if err != nil {
					t.Errorf("Unexpected error in normal check for endpoint %s: %v", tc.endpoint, err)
				}
				if resultNormal != tc.expectNormal {
					t.Errorf("Normal check - Endpoint %s: expected %v, got %v", tc.endpoint, tc.expectNormal, resultNormal)
				}

				// Strict check
				resultStrict, err := sentinel.StrictCheck(tc.endpoint, tt.principal, nil)
				if err != nil {
					t.Errorf("Unexpected error in strict check for endpoint %s: %v", tc.endpoint, err)
				}
				if resultStrict != tc.expectStrict {
					t.Errorf("Strict check - Endpoint %s: expected %v, got %v", tc.endpoint, tc.expectStrict, resultStrict)
				}
			}
		})
	}
}

func TestSentinel_CustomParameters(t *testing.T) {
	tests := []struct {
		name      string
		endpoints map[string]string
		testCases []struct {
			endpoint string
			custom   map[string]string
			expected bool
		}
		principal *sentinelTestPrincipal
	}{
		{
			name: "Custom parameter usage",
			endpoints: map[string]string{
				"GET /api/data": "allow: Role('user') and #env == 'development'",
			},
			testCases: []struct {
				endpoint string
				custom   map[string]string
				expected bool
			}{
				{
					endpoint: "GET /api/data",
					custom:   map[string]string{"env": "development"},
					expected: true,
				},
				{
					endpoint: "GET /api/data",
					custom:   map[string]string{"env": "production"},
					expected: false,
				},
			},
			principal: &sentinelTestPrincipal{
				roles: []string{"user"},
			},
		},
		{
			name: "Multiple custom parameters",
			endpoints: map[string]string{
				"POST /api/upload": "allow: #action == 'upload' and #resource == 'document' and Role('uploader')",
			},
			testCases: []struct {
				endpoint string
				custom   map[string]string
				expected bool
			}{
				{
					endpoint: "POST /api/upload",
					custom: map[string]string{
						"action":   "upload",
						"resource": "document",
					},
					expected: true,
				},
				{
					endpoint: "POST /api/upload",
					custom: map[string]string{
						"action":   "download",
						"resource": "document",
					},
					expected: false,
				},
			},
			principal: &sentinelTestPrincipal{
				roles: []string{"uploader"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel, err := NewSentinel()
			if err != nil {
				t.Fatalf("Failed to create sentinel: %v", err)
			}

			// Add endpoints
			for endpoint, express := range tt.endpoints {
				err = sentinel.AddEndpoint(endpoint, express)
				if err != nil {
					t.Fatalf("Failed to add endpoint %s: %v", endpoint, err)
				}
			}

			// Test cases
			for _, tc := range tt.testCases {
				result, err := sentinel.Check(tc.endpoint, tt.principal, tc.custom)
				if err != nil {
					t.Errorf("Unexpected error for endpoint %s: %v", tc.endpoint, err)
				}
				if result != tc.expected {
					t.Errorf("Endpoint %s: expected %v, got %v", tc.endpoint, tc.expected, result)
				}
			}
		})
	}
}

func TestSentinel_CleanEndpoints(t *testing.T) {
	sentinel, err := NewSentinel()
	if err != nil {
		t.Fatalf("Failed to create sentinel: %v", err)
	}

	// Add some endpoints
	err = sentinel.AddEndpoint("GET /api/users", "allow: Role('admin')")
	if err != nil {
		t.Fatalf("Failed to add endpoint: %v", err)
	}

	err = sentinel.AddEndpoint("POST /api/users", "allow: Role('admin')")
	if err != nil {
		t.Fatalf("Failed to add endpoint: %v", err)
	}

	// Verify endpoints work
	principal := &sentinelTestPrincipal{roles: []string{"admin"}}
	result, err := sentinel.Check("GET /api/users", principal, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !result {
		t.Error("Expected true before cleaning endpoints")
	}

	// Clean endpoints
	sentinel.CleanEndpoints()

	// Verify endpoints are gone (should fail because no routes exist)
	result, err = sentinel.Check("GET /api/users", principal, nil)
	if err == nil {
		t.Error("Expected error after cleaning endpoints")
	}

	// Add new endpoint after cleaning
	err = sentinel.AddEndpoint("GET /api/users", "deny: Role('admin')")
	if err != nil {
		t.Fatalf("Failed to add endpoint after cleaning: %v", err)
	}

	result, err = sentinel.Check("GET /api/users", principal, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result {
		t.Error("Expected false for deny rule")
	}
}

func TestSentinel_WithConfig(t *testing.T) {
	// Create a temporary config file
	configContent := `# Test configuration
GET /api/users, allow: Role('admin')
POST /api/users, allow: Permission('user.create')
/api/public, allow: 1 == 1
GET /api/books?category=:category, allow: $category == 'public'
# Comment line should be ignored
GET/POST /api/files/*, allow: Role('filemanager')`

	tmpFile, err := os.CreateTemp("", "test_rules_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(configContent)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	// Test creating sentinel with config
	sentinel, err := NewSentinel(WithConfig(tmpFile.Name()))
	if err != nil {
		t.Fatalf("Failed to create sentinel with config: %v", err)
	}

	tests := []struct {
		endpoint  string
		principal *sentinelTestPrincipal
		custom    map[string]string
		expected  bool
	}{
		{
			endpoint:  "GET /api/users",
			principal: &sentinelTestPrincipal{roles: []string{"admin"}},
			expected:  true,
		},
		{
			endpoint:  "GET /api/users",
			principal: &sentinelTestPrincipal{roles: []string{"user"}},
			expected:  false,
		},
		{
			endpoint:  "POST /api/users",
			principal: &sentinelTestPrincipal{permissions: []string{"user.create"}},
			expected:  true,
		},
		{
			endpoint:  "/api/public",
			principal: &sentinelTestPrincipal{},
			expected:  true,
		},
		{
			endpoint:  "GET /api/books?category=public",
			principal: &sentinelTestPrincipal{},
			expected:  true,
		},
		{
			endpoint:  "GET /api/books?category=private",
			principal: &sentinelTestPrincipal{},
			expected:  false,
		},
		{
			endpoint:  "GET /api/files/public/doc.pdf",
			principal: &sentinelTestPrincipal{roles: []string{"filemanager"}},
			expected:  true,
		},
		{
			endpoint:  "GET /api/files/secret",
			principal: &sentinelTestPrincipal{roles: []string{"filemanager"}},
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			result, err := sentinel.Check(tt.endpoint, tt.principal, tt.custom)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSentinel_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		setup     func() (Sentinel, error)
		endpoint  string
		principal *sentinelTestPrincipal
		custom    map[string]string
		wantError bool
		expected  bool
	}{
		{
			name: "Non-existent endpoint",
			setup: func() (Sentinel, error) {
				s, err := NewSentinel()
				if err != nil {
					return nil, err
				}
				return s, s.AddEndpoint("GET /api/users", "allow: Role('admin')")
			},
			endpoint:  "GET /api/nonexistent",
			principal: &sentinelTestPrincipal{roles: []string{"admin"}},
			wantError: true, // Should return error when no route matches
		},
		{
			name: "Nil principal",
			setup: func() (Sentinel, error) {
				s, err := NewSentinel()
				if err != nil {
					return nil, err
				}
				return s, s.AddEndpoint("GET /api/users", "allow: Role('admin')")
			},
			endpoint:  "GET /api/users",
			principal: nil,
			wantError: true,
		},
		{
			name: "Empty endpoint",
			setup: func() (Sentinel, error) {
				s, err := NewSentinel()
				if err != nil {
					return nil, err
				}
				return s, s.AddEndpoint("GET /api/users", "allow: Role('admin')")
			},
			endpoint:  "",
			principal: &sentinelTestPrincipal{roles: []string{"admin"}},
			wantError: true,
		},
		{
			name: "Malformed endpoint",
			setup: func() (Sentinel, error) {
				s, err := NewSentinel()
				if err != nil {
					return nil, err
				}
				return s, s.AddEndpoint("GET /api/users", "allow: Role('admin')")
			},
			endpoint:  "INVALID ENDPOINT FORMAT",
			principal: &sentinelTestPrincipal{roles: []string{"admin"}},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel, err := tt.setup()
			if err != nil {
				t.Fatalf("Failed to setup sentinel: %v", err)
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
				result, checkErr = sentinel.Check(tt.endpoint, tt.principal, tt.custom)
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

func TestSentinel_RouteMatchingErrors(t *testing.T) {
	tests := []struct {
		name      string
		endpoints map[string]string
		testCases []struct {
			endpoint  string
			principal *sentinelTestPrincipal
			custom    map[string]string
			wantError bool
			expected  bool
		}
	}{
		{
			name: "Method not found in routing table",
			endpoints: map[string]string{
				"GET /api/users": "allow: Role('admin')",
			},
			testCases: []struct {
				endpoint  string
				principal *sentinelTestPrincipal
				custom    map[string]string
				wantError bool
				expected  bool
			}{
				{
					endpoint:  "POST /api/users",
					principal: &sentinelTestPrincipal{roles: []string{"admin"}},
					wantError: true, // Router should return error for no matching route
					expected:  false,
				},
				{
					endpoint:  "DELETE /api/nonexistent",
					principal: &sentinelTestPrincipal{roles: []string{"admin"}},
					wantError: true, // Router should return error for no matching route
					expected:  false,
				},
			},
		},
		{
			name: "Path not found in routing table",
			endpoints: map[string]string{
				"GET /api/users/:id": "allow: Role('admin')",
			},
			testCases: []struct {
				endpoint  string
				principal *sentinelTestPrincipal
				custom    map[string]string
				wantError bool
				expected  bool
			}{
				{
					endpoint:  "GET /api/posts/123",
					principal: &sentinelTestPrincipal{roles: []string{"admin"}},
					wantError: true, // Router should return error for no matching route
					expected:  false,
				},
				{
					endpoint:  "GET /api/completely/different/path",
					principal: &sentinelTestPrincipal{roles: []string{"admin"}},
					wantError: true, // Router should return error for no matching route
					expected:  false,
				},
			},
		},
		{
			name: "Query parameter mismatch in strict mode",
			endpoints: map[string]string{
				"GET /api/books?category=:category": "allow: Role('user')",
			},
			testCases: []struct {
				endpoint  string
				principal *sentinelTestPrincipal
				custom    map[string]string
				wantError bool
				expected  bool
			}{
				{
					endpoint:  "GET /api/books?category=fiction&page=1",
					principal: &sentinelTestPrincipal{roles: []string{"user"}},
					wantError: false,
					expected:  true, // Normal check should pass (ignores extra params)
				},
			},
		},
		{
			name: "Invalid method format",
			endpoints: map[string]string{
				"GET /api/users": "allow: Role('admin')",
			},
			testCases: []struct {
				endpoint  string
				principal *sentinelTestPrincipal
				custom    map[string]string
				wantError bool
				expected  bool
			}{
				{
					endpoint:  "INVALID_METHOD /api/users",
					principal: &sentinelTestPrincipal{roles: []string{"admin"}},
					wantError: true, // Router should return error for invalid method
					expected:  false,
				},
			},
		},
		{
			name:      "Empty routing table",
			endpoints: map[string]string{}, // No endpoints added
			testCases: []struct {
				endpoint  string
				principal *sentinelTestPrincipal
				custom    map[string]string
				wantError bool
				expected  bool
			}{
				{
					endpoint:  "GET /api/users",
					principal: &sentinelTestPrincipal{roles: []string{"admin"}},
					wantError: true, // Router should return error when no routes exist
					expected:  false,
				},
				{
					endpoint:  "POST /api/anything",
					principal: &sentinelTestPrincipal{},
					wantError: true, // Router should return error when no routes exist
					expected:  false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel, err := NewSentinel()
			if err != nil {
				t.Fatalf("Failed to create sentinel: %v", err)
			}

			// Add endpoints
			for endpoint, express := range tt.endpoints {
				err = sentinel.AddEndpoint(endpoint, express)
				if err != nil {
					t.Fatalf("Failed to add endpoint %s: %v", endpoint, err)
				}
			}

			// Test cases
			for _, tc := range tt.testCases {
				result, err := sentinel.Check(tc.endpoint, tc.principal, tc.custom)
				if tc.wantError {
					if err == nil {
						t.Errorf("Expected error for endpoint %s but got none", tc.endpoint)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for endpoint %s: %v", tc.endpoint, err)
					}
					if result != tc.expected {
						t.Errorf("Endpoint %s: expected %v, got %v", tc.endpoint, tc.expected, result)
					}
				}
			}
		})
	}
}

func TestSentinel_StrictCheck_RouteMatchingErrors(t *testing.T) {
	tests := []struct {
		name      string
		endpoints map[string]string
		testCases []struct {
			endpoint  string
			principal *sentinelTestPrincipal
			wantError bool
			expected  bool
		}
	}{
		{
			name: "Strict check with query parameter mismatch",
			endpoints: map[string]string{
				"GET /api/books?category=:category": "allow: Role('user')",
			},
			testCases: []struct {
				endpoint  string
				principal *sentinelTestPrincipal
				wantError bool
				expected  bool
			}{
				{
					endpoint:  "GET /api/books?category=fiction&page=1",
					principal: &sentinelTestPrincipal{roles: []string{"user"}},
					wantError: false, // Strict check should pass - extra params are allowed
					expected:  true,
				},
				{
					endpoint:  "GET /api/books?category=fiction",
					principal: &sentinelTestPrincipal{roles: []string{"user"}},
					wantError: false,
					expected:  true, // Strict check should pass with exact params
				},
				{
					endpoint:  "GET /api/books", // Missing required query param
					principal: &sentinelTestPrincipal{roles: []string{"user"}},
					wantError: true,
					expected:  false,
				},
			},
		},
		{
			name: "Strict check with no matching route",
			endpoints: map[string]string{
				"GET /api/users?id=:id": "allow: Role('admin')",
			},
			testCases: []struct {
				endpoint  string
				principal *sentinelTestPrincipal
				wantError bool
				expected  bool
			}{
				{
					endpoint:  "GET /api/posts?id=123",
					principal: &sentinelTestPrincipal{roles: []string{"admin"}},
					wantError: true, // Router should return error for no matching route
					expected:  false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel, err := NewSentinel()
			if err != nil {
				t.Fatalf("Failed to create sentinel: %v", err)
			}

			// Add endpoints
			for endpoint, express := range tt.endpoints {
				err = sentinel.AddEndpoint(endpoint, express)
				if err != nil {
					t.Fatalf("Failed to add endpoint %s: %v", endpoint, err)
				}
			}

			// Test cases
			for _, tc := range tt.testCases {
				result, err := sentinel.StrictCheck(tc.endpoint, tc.principal, nil)
				if tc.wantError {
					if err == nil {
						t.Errorf("Expected error for strict check endpoint %s but got none", tc.endpoint)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for strict check endpoint %s: %v", tc.endpoint, err)
					}
					if result != tc.expected {
						t.Errorf("Strict check endpoint %s: expected %v, got %v", tc.endpoint, tc.expected, result)
					}
				}
			}
		})
	}
}

func BenchmarkSentinel_SimpleRouting(b *testing.B) {
	sentinel, err := NewSentinel()
	if err != nil {
		b.Fatalf("Failed to create sentinel: %v", err)
	}

	err = sentinel.AddEndpoint("GET /api/users", "allow: Role('admin')")
	if err != nil {
		b.Fatalf("Failed to add endpoint: %v", err)
	}

	principal := &sentinelTestPrincipal{
		roles: []string{"admin"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sentinel.Check("GET /api/users", principal, nil)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkSentinel_ComplexRouting(b *testing.B) {
	sentinel, err := NewSentinel()
	if err != nil {
		b.Fatalf("Failed to create sentinel: %v", err)
	}

	endpoints := map[string]string{
		"GET /api/users":                      "allow: Role('admin') or Permission('user.read')",
		"POST /api/users":                     "allow: Role('admin') and Permission('user.create')",
		"GET /api/users/:id":                  "allow: Role('admin') or $id == 'self'",
		"DELETE /api/users/:id":               "deny: Role('guest')",
		"GET /api/files/*":                    "allow: Role('filemanager')",
		"GET /api/books?category=:category":   "allow: Permission('book.read') or $category == 'public'",
		"POST /api/orders?priority=:priority": "allow: Role('manager') and $priority != 'urgent'",
	}

	for endpoint, express := range endpoints {
		err = sentinel.AddEndpoint(endpoint, express)
		if err != nil {
			b.Fatalf("Failed to add endpoint %s: %v", endpoint, err)
		}
	}

	principal := &sentinelTestPrincipal{
		roles:       []string{"admin"},
		permissions: []string{"user.read", "user.create", "book.read"},
	}

	testEndpoints := []string{
		"GET /api/users",
		"POST /api/users",
		"GET /api/users/123",
		"DELETE /api/users/123",
		"GET /api/files/public/doc.pdf",
		"GET /api/books?category=fiction",
		"POST /api/orders?priority=normal",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		endpoint := testEndpoints[i%len(testEndpoints)]
		_, err := sentinel.Check(endpoint, principal, nil)
		if err != nil {
			b.Fatalf("Unexpected error for endpoint %s: %v", endpoint, err)
		}
	}
}

func BenchmarkSentinel_StrictCheck(b *testing.B) {
	sentinel, err := NewSentinel()
	if err != nil {
		b.Fatalf("Failed to create sentinel: %v", err)
	}

	err = sentinel.AddEndpoint("GET /api/books?category=:category&sort=:sort", "allow: Role('user')")
	if err != nil {
		b.Fatalf("Failed to add endpoint: %v", err)
	}

	principal := &sentinelTestPrincipal{
		roles: []string{"user"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sentinel.StrictCheck("GET /api/books?category=fiction&sort=title", principal, nil)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkSentinel_WithManyEndpoints(b *testing.B) {
	sentinel, err := NewSentinel()
	if err != nil {
		b.Fatalf("Failed to create sentinel: %v", err)
	}

	// Add many endpoints to test performance with large routing tables
	for i := range 100 {
		endpoint := fmt.Sprintf("GET /api/resource%d", i)
		express := "allow: Role('user')"
		err = sentinel.AddEndpoint(endpoint, express)
		if err != nil {
			b.Fatalf("Failed to add endpoint: %v", err)
		}
	}

	principal := &sentinelTestPrincipal{
		roles: []string{"user"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		endpoint := fmt.Sprintf("GET /api/resource%d", i%100)
		_, err := sentinel.Check(endpoint, principal, nil)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}
