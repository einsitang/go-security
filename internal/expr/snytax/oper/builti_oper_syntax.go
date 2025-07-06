package oper

import (
	"github.com/einsitang/go-security/internal/expr/ctx"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

type builtiOperSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
	evalute     func(a, b syntax.SyntaxValue) syntax.SyntaxValue
}

// 语句优先级
func (s *builtiOperSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *builtiOperSyntax) Kind() int {
	return s.kind
}

// 入参类型要求
func (s *builtiOperSyntax) InputType() int {
	return syntax.Type_Bool | syntax.Type_Number | syntax.Type_String
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *builtiOperSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *builtiOperSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *builtiOperSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *builtiOperSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *builtiOperSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *builtiOperSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	leftR := s.left.Evaluate(c)
	rightR := s.right.Evaluate(c)
	if leftR.IsError {
		return syntax.SyntaxValue{
			IsError: true,
			Error:   leftR.Error,
		}
	}

	if rightR.IsError {
		return syntax.SyntaxValue{
			IsError: true,
			Error:   rightR.Error,
		}
	}

	return s.evalute(leftR, rightR)
}
