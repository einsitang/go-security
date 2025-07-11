package expr

import (
	"testing"

	"github.com/einsitang/go-security/internal/expr/ctx"
	"github.com/einsitang/go-security/internal/expr/tokenizer"
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

func BenchmarkAnalyzer(b *testing.B) {
	input := "allow:Role('admin') and !($x % 5 == 2) or (Permission('doc:data') and $category == 'guest')"
	analyzer := NewAnalyzer()
	syntaxTree, err := analyzer.Parse(input)
	if err != nil {
		b.Fatal(err)
		return
	}
	params := make(map[string]any)
	params["category"] = "computer"
	params["x"] = 4
	context := &ctx.Context{
		Principal: &principal{
			roles: []string{"admin"},
		},
		Params: params,
	}
	b.Logf("N( %d ) - %s \n", b.N, input)

	var pass bool
	for i := 0; i < b.N; i++ {
		pass = syntaxTree.Syntax.Evaluate(context).Value.(bool)
		// b.Logf("N( %d ) - cheked ( %s ): %v \n", b.N, syntaxTree.Policy, syntaxTree.Syntax.Evaluate(context).Value)

	}
	b.Logf("N( %d ) pass: %v \n", b.N, pass)
}

func TestTokenizeParse(t *testing.T) {
	_tokenizer := tokenizer.New()
	_tokenizer.DefineTokens(TPolicy, []string{"allow", "deny"}) // Policy
	_tokenizer.DefineTokens(TBuiltinFunction, []string{
		"Role", "Permission", "Group", "Roles", "Permissions", "Groups",
	}, tokenizer.AloneTokenOption) // 内置单元函数
	_tokenizer.DefineTokens(TCurlyOpen, []string{"("})
	_tokenizer.DefineTokens(TCurlyClose, []string{")"})
	_tokenizer.DefineTokens(TNegate, []string{"!"})                                  // 逻辑运算符 单元
	_tokenizer.DefineTokens(TMath, []string{"+", "-", "/", "*", "%"})                // 运算符 双元
	_tokenizer.DefineTokens(TComparison, []string{"<", "<=", ">=", ">", "==", "!="}) // 逻辑运算符 双元
	_tokenizer.DefineTokens(TLogic, []string{"and", "or"})                           // 逻辑符 双元
	_tokenizer.DefineTokens(TDot, []string{"."})
	_tokenizer.DefineTokens(TComma, []string{","})
	_tokenizer.DefineStringToken(TDoubleQuoted, `"`, `"`)
	_tokenizer.DefineStringToken(TSignleQuoted, `'`, `'`)
	_tokenizer.DefineTokens(TPlaceholder, []string{"$"})
	_tokenizer.DefineTokens(TCustomParam, []string{"#"})
	_tokenizer.AllowKeywordSymbols(tokenizer.Underscore, tokenizer.Numbers)

	input := "Roless('hello','world')"
	stream := _tokenizer.ParseString(input)
	for stream.IsValid() {
		token := stream.CurrentToken()
		t.Logf("[%d:%d] token( %v ): %s \n", token.Line(), token.Offset(), token.Key(), token.ValueString())
		stream.GoNext()
	}
}

func TestAnalyzer(t *testing.T) {
	// input := "allow:(Role('admin') and Permission('doc:read'))"
	// input := "allow:Role('admin') and $x % 5 == 3 or Permission('doc:data') and $category == 'computer'"
	// input := "allow:Role('admin') and $x / 2 == 4 or ( Permission('doc:read') and $ category == 'guest')"
	// input := "allow:Role('admin') and 1+1==2 or Permission('doc:data')"
	// input := "allow:Permission('doc:read') and $category == 'guest'"
	// input := "allow:!((1 + 1) * 4 == 18)"
	// input := "allow:Role('admin')"
	input := "allow:Roles('admin','manager') and Permissions('read') and #x == 8 and $x / $x == 1"
	t.Logf("\n%s \n", input)
	_analyzer := NewAnalyzer()
	_analyzer.DebugTokens(input)
	st, err := _analyzer.Parse(input)
	if err != nil {
		t.Error(err)
		return
	}
	params := make(map[string]any)
	params["category"] = "computer"
	params["x"] = 4
	context := &ctx.Context{
		Principal: &principal{
			roles:       []string{"admin"},
			permissions: []string{"read", "execute"},
		},
		Params: params,
		CustomParams: map[string]string{
			"x": "8",
		},
	}

	DebugAst(st)
	t.Logf("cheked ( %s ): %v \n", st.Policy, st.Syntax.Evaluate(context).Value)

}
