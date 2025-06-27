package oper

import (
	"github.com/einsitang/go-security/internal/expr/ctx"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

// and logic syntax
type andSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *andSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *andSyntax) Kind() int {
	return s.kind
}

func (s *andSyntax) InputType() int {
	return syntax.Type_Bool
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *andSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *andSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *andSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *andSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *andSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *andSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	return syntax.SyntaxValue{
		Type:  syntax.Type_Bool,
		Value: s.left.Evaluate(c).Value.(bool) && s.right.Evaluate(c).Value.(bool),
	}
}

func NewAndSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &andSyntax{
		kind:     2,
		priority: 60,
		left:     left,
		right:    right,
	}
}

// or logic syntax
type orSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *orSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *orSyntax) Kind() int {
	return s.kind
}

func (s *orSyntax) InputType() int {
	return syntax.Type_Bool
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *orSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *orSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *orSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *orSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *orSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *orSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	return syntax.SyntaxValue{
		Type:  syntax.Type_Bool,
		Value: s.left.Evaluate(c).Value.(bool) || s.right.Evaluate(c).Value.(bool),
	}
}

func NewOrSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &orSyntax{
		kind:     2,
		priority: 60,
		left:     left,
		right:    right,
	}
}
