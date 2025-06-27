package security

import (
	"io"
	"log"
	"os"
	"strings"

	"github.com/einsitang/go-security/internal/expr"
	"github.com/einsitang/go-security/internal/expr/ctx"
	"github.com/einsitang/go-security/internal/parse"
)

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

	checked := syntaxTree.Syntax.Evaluate(&ctx.Context{
		Params:    params,
		Principal: principal,
	}).Value.(bool)
	policy := syntaxTree.Policy

	if policy == "allow" {
		return checked, nil
	}

	// else policy == demy
	return !checked, nil
}

func (se *se) CleanEndpoints() {
	se.router = parse.NewRouter([]string{})
	se.expression = make(map[string]*expr.SyntaxTree)
	se.analyzer = expr.NewAnalyzer()
}

type SecurityOption func(se *se)

func WithConfig(configPath string) SecurityOption {
	file, err := os.Open(configPath)
	if err != nil {
		panic(err)
	}
	defer func() {
		file.Close()
	}()
	content, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}

	text := string(content)

	return func(se *se) {
		lines := strings.Split(text, "\n")
		for _, line := range lines {
			endpoint, express, ok := strings.Cut(line, ",")
			if !ok {
				log.Println("invalid line:", line)
				continue
			}
			se.RegEndpoint(endpoint, express)
		}
	}
}

func NewSecurity(options ...SecurityOption) Security {
	_se := &se{
		router:     parse.NewRouter([]string{}),
		expression: make(map[string]*expr.SyntaxTree),
		analyzer:   expr.NewAnalyzer(),
	}

	for _, option := range options {
		option(_se)
	}
	return _se
}
