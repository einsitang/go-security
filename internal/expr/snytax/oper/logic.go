package oper

import (
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

// and logic syntax
type andSyntax struct {
	builtiOperSyntax
}

func (s *andSyntax) InputType() int {
	return syntax.Type_Bool
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *andSyntax) ReturnType() int {
	return syntax.Type_Bool
}

func NewAndSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &andSyntax{
		builtiOperSyntax{
			kind:     2,
			priority: 60,
			left:     left,
			right:    right,
			evalute: func(a, b syntax.SyntaxValue) syntax.SyntaxValue {
				return syntax.SyntaxValue{
					Type:  syntax.Type_Bool,
					Value: a.Value.(bool) && b.Value.(bool),
				}
			},
		},
	}
}

// or logic syntax
type orSyntax struct {
	builtiOperSyntax
}

func (s *orSyntax) InputType() int {
	return syntax.Type_Bool
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *orSyntax) ReturnType() int {
	return syntax.Type_Bool
}

func NewOrSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &orSyntax{
		builtiOperSyntax{
			kind:     2,
			priority: 60,
			left:     left,
			right:    right,
			evalute: func(a, b syntax.SyntaxValue) syntax.SyntaxValue {
				return syntax.SyntaxValue{
					Type:  syntax.Type_Bool,
					Value: a.Value.(bool) || b.Value.(bool),
				}
			},
		},
	}
}
