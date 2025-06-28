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

func TestSecurity(t *testing.T) {
	rulePath := "./rule.txt"
	security := NewSecurity(WithConfig(rulePath))
	// security.RegEndpoint("/api/v1/books?category=:category", "allow:Role('admin') and $category == '2'")

	_principal := &principal{
		roles: []string{"admin"},
	}
	begin := time.Now()
	endpoint := "GET /api/v1/books?category=2"
	// endpoint := "/api/v1/files/2025/05/22"
	pass, err := security.Guard(endpoint, _principal)
	end := time.Now()
	totalTime := end.UnixMicro() - begin.UnixMicro()
	t.Logf("pass: %v, err: %v, total time: %v microsecond \n", pass, err, totalTime)

}
