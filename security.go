package security

import (
	"github.com/einsitang/go-security/internal/expr"
	"github.com/einsitang/go-security/internal/expr/ctx"
	"github.com/einsitang/go-security/internal/parse"
)

type security struct {
}

type Security interface {
	RegEndpoint(endpoint string, express string) error
	Guard(endpoint string, principal ctx.Principal) (bool, error)
	CleanEndpoints()
}

type se struct {
	router     *parse.Router
	expression map[string]*expr.SyntaxTree
	analyzer   expr.SyntaxAnalyzer
}

func (se *se) RegEndpoint(endpoint string, express string) error {
	se.router.Add(endpoint)
	se.expression[endpoint] = se.analyzer.Parse(express)
	return nil
}

func (se *se) Guard(endpoint string, principal ctx.Principal) (bool, error) {
	match, params, err := se.router.Match(endpoint)
	if err != nil {
		return false, err
	}

	syntaxTree, ok := se.expression[match]
	if !ok {
		return true, nil
	}

	return syntaxTree.Syntax.Evaluate(&ctx.Context{
		Params:    params,
		Principal: principal,
	}).Value.(bool), nil
}

func (se *se) CleanEndpoints() {
	se.router = parse.NewRouter([]string{})
	se.expression = make(map[string]*expr.SyntaxTree)
	se.analyzer = expr.NewAnalyzer()
}

func NewSecurity() Security {
	return &se{
		router:     parse.NewRouter([]string{}),
		expression: make(map[string]*expr.SyntaxTree),
		analyzer:   expr.NewAnalyzer(),
	}
}

// func NewFromConfig(config string) (Security, error) {
// 	// 解析配置并创建 Security 实例
// 	security := &securityContext{
// 		config: config,
// 	}
// 	return security, nil
// }
