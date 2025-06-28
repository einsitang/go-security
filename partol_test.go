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

func TestPartol(t *testing.T) {
	rulePath := "./rule.txt"
	p, err := NewPartol(WithConfig(rulePath))
	if err != nil {
		panic(err)
	}

	// security.RegEndpoint("/api/v1/books?category=:category", "allow:Role('admin') and $category == '2'")

	_principal := &principal{
		roles: []string{"admin"},
	}
	begin := time.Now()
	endpoint := "GET /api/v1/books?category=2"
	// endpoint := "/api/v1/files/2025/05/22"
	pass, err := p.Check(endpoint, _principal)
	end := time.Now()
	totalTime := end.UnixMicro() - begin.UnixMicro()
	if err != nil {
		t.Logf("error: %v \n", err)

	} else {
		t.Logf("pass: %v, total time: %v microsecond \n", pass, totalTime)
	}

}
