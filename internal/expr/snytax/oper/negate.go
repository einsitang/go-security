package oper

import (
	"github.com/einsitang/go-security/internal/expr/ctx"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

// ! negate syntax
type negateSyntax struct {
	priority int
	kind     int
	val      syntax.Syntax
}

func (s *negateSyntax) Priority() int {
	return s.priority
}

func (s *negateSyntax) Kind() int {
	return s.kind
}

func (s *negateSyntax) Left() syntax.Syntax {
	return s.val
}

func (s *negateSyntax) Right() syntax.Syntax {
	panic("Syntax not support right value")
}

func (s *negateSyntax) ChangeLeft(left syntax.Syntax) {
	s.val = left
}

func (s *negateSyntax) ChangeRight(right syntax.Syntax) {
	panic("Syntax not support right value")
}

func (s *negateSyntax) InputType() int {
	return syntax.Type_Bool
}

// 出参类型
func (s *negateSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 运行求值
func (s *negateSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	return syntax.SyntaxValue{
		Type:  syntax.Type_Bool,
		Value: !s.val.Evaluate(c).Value.(bool),
	}
}

func NewNegateSyntax(val syntax.Syntax) syntax.Syntax {
	return &negateSyntax{
		priority: 20,
		kind:     1,
		val:      val,
	}
}
