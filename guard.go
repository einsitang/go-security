package security

import (
	"log"
	"reflect"

	"github.com/einsitang/go-security/internal/expr"
	"github.com/einsitang/go-security/internal/expr/ctx"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

var analyzer = expr.NewAnalyzer()

type Guard interface {
	Express() string
	Check(context *SecurityContext) bool
}

type guard struct {
	express    string
	syntaxTree *expr.SyntaxTree
}

func (g *guard) Express() string {
	return g.express
}

func (g *guard) Check(context *SecurityContext) bool {
	st := g.syntaxTree
	eval := st.Syntax.Evaluate((*ctx.Context)(context))
	if eval.Type != syntax.Type_Bool {
		log.Printf("[warnning]evaluate return value not type bool , result.type:%v , result.value:%v \n", reflect.TypeOf(eval.Type).String(), eval.Value)
		return false
	}
	checked := eval.Value.(bool)
	policy := st.Policy
	if policy == "allow" {
		return checked
	}
	return !checked
}

func NewGuard(express string) (Guard, error) {
	st, err := analyzer.Parse(express)
	if err != nil {
		return nil, err
	}
	return &guard{
		express:    express,
		syntaxTree: st,
	}, nil
}
