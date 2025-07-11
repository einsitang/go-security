package security

import (
	"testing"
	"time"
)

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

func TestSentinel(t *testing.T) {
	sentinel, err := NewSentinel()
	if err != nil {
		panic(err)
	}
	rulemap := map[string]string{
		"/api/v1/books?category=:category": "allow:Role('admin') and $category == 2",
		"/api/v1/users":                    "allow:Role('manager') or #ENV != 'PROD'",
	}

	for pattern, express := range rulemap {
		sentinel.AddEndpoint(pattern, express)
	}

	_principal := &principal{
		roles: []string{"admin"},
	}
	customParams := map[string]string{
		"ENV": "DEV",
	}

	testmap := map[string]bool{
		"/api/v1/books?category=2": true,
		"/api/v1/books?category=a": false,
		"/api/v1/users":            true,
	}

	for endpoint, expect := range testmap {
		pass, err := sentinel.Check(endpoint, _principal, customParams)
		if err != nil {
			t.Errorf("Unexpected error for endpoint %s: %v", endpoint, err)
		}
		if pass != expect {
			t.Errorf("Expected %v for endpoint %s, but got %v", expect, endpoint, pass)
		}

	}

}

func TestSentinelWithRuleFile(t *testing.T) {
	rulePath := "./rule.txt"
	sentinel, err := NewSentinel(WithConfig(rulePath))
	if err != nil {
		panic(err)
	}

	// security.RegEndpoint("/api/v1/books?category=:category", "allow:Role('admin') and $category == '2'")

	_principal := &principal{
		roles: []string{"admin"},
	}
	begin := time.Now()
	// endpoint := "GET /api/v1/books?category=2"
	endpoint := "/api/v1/test"
	pass, err := sentinel.Check(endpoint, _principal, nil)
	end := time.Now()
	totalTime := end.UnixMicro() - begin.UnixMicro()
	if err != nil {
		t.Logf("error: %v \n", err)

	} else {
		t.Logf("pass: %v, total time: %v microsecond \n", pass, totalTime)
	}

}
