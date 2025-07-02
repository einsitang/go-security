package security

import (
	"testing"
	"time"

	"github.com/bzick/tokenizer"
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

func TestTokenizeParse(t *testing.T) {
	THello := tokenizer.TokenKey(100)
	TWorld := tokenizer.TokenKey(101)
	TRoleKey := tokenizer.TokenKey(105)
	TAndKey := tokenizer.TokenKey(106)

	parser := tokenizer.New()
	// ignore case
	parser.DefineTokens(THello, []string{"hello"}, tokenizer.AloneTokenOption)
	parser.DefineTokens(TRoleKey, []string{"Role"})
	parser.DefineTokens(TWorld, []string{"world"})
	parser.DefineTokens(TAndKey, []string{"and"})
	input := "helloworld can match,prefixWorld role and roles both not match,but Role and WorLd is match will"
	stream := parser.ParseString(input)
	for stream.IsValid() {
		token := stream.CurrentToken()
		t.Logf("[%d:%d] %s %v", token.Line(), token.Offset(), token.ValueString(), token.Key())
		stream.GoNext()
	}
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
	// endpoint := "GET /api/v1/books?category=2"
	endpoint := "/api/v1/test"
	pass, err := p.Check(endpoint, _principal)
	end := time.Now()
	totalTime := end.UnixMicro() - begin.UnixMicro()
	if err != nil {
		t.Logf("error: %v \n", err)

	} else {
		t.Logf("pass: %v, total time: %v microsecond \n", pass, totalTime)
	}

}
