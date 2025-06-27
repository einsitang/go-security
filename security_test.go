package security

import (
	"testing"
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
	security := NewSecurity()
	security.RegEndpoint("/api/v1/books?category=:category", "allow:Role('admin') and $category == '2'")

	_principal := &principal{
		roles: []string{"admin"},
	}
	endPoint := "/api/v1/books?category=2"
	pass, err := security.Guard(endPoint, _principal)
	t.Logf("pass: %v, err: %v", pass, err)

}
