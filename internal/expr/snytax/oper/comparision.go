package oper

import (
	"github.com/einsitang/go-security/internal/expr/ctx"

	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

type eqSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *eqSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *eqSyntax) Kind() int {
	return s.kind
}

func (s *eqSyntax) InputType() int {
	return syntax.Type_Bool | syntax.Type_Number | syntax.Type_String
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *eqSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *eqSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *eqSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *eqSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *eqSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *eqSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	return syntax.SyntaxValue{
		Type:  syntax.Type_Bool,
		Value: s.left.Evaluate(c).Value == s.right.Evaluate(c).Value,
	}
}

func NewEqSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &eqSyntax{
		kind:     2,
		priority: 55,
		left:     left,
		right:    right,
	}
}

// !=
// not equals syntax
type notEqSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *notEqSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *notEqSyntax) Kind() int {
	return s.kind
}

func (s *notEqSyntax) InputType() int {
	return syntax.Type_Bool | syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *notEqSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *notEqSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *notEqSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *notEqSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *notEqSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *notEqSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	return syntax.SyntaxValue{
		Type:  syntax.Type_Bool,
		Value: s.left.Evaluate(c).Value != s.right.Evaluate(c).Value,
	}
}

func NewNotEqSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &notEqSyntax{
		kind:     2,
		priority: 55,
		left:     left,
		right:    right,
	}
}

// <
// lt syntax
type ltSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *ltSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *ltSyntax) Kind() int {
	return s.kind
}

func (s *ltSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *ltSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *ltSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *ltSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *ltSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *ltSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *ltSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	leftR := s.left.Evaluate(c)
	rightR := s.right.Evaluate(c)
	leftIfnerType := syntax.InferType(leftR.Value)
	rightInferType := syntax.InferType(rightR.Value)
	if leftIfnerType == syntax.Type_Number && leftIfnerType == rightInferType {
		return syntax.SyntaxValue{
			Type:  syntax.Type_Bool,
			Value: leftR.Value.(float32) < rightR.Value.(float32),
		}
	}
	panic("type error")
}

func NewLtSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &ltSyntax{
		kind:     2,
		priority: 50,
		left:     left,
		right:    right,
	}
}

// <=
// lte syntax
type lteSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *lteSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *lteSyntax) Kind() int {
	return s.kind
}

func (s *lteSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *lteSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *lteSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *lteSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *lteSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *lteSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *lteSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	leftR := s.left.Evaluate(c)
	rightR := s.right.Evaluate(c)
	leftIfnerType := syntax.InferType(leftR.Value)
	rightInferType := syntax.InferType(rightR.Value)
	if leftIfnerType == syntax.Type_Number && leftIfnerType == rightInferType {
		return syntax.SyntaxValue{
			Type:  syntax.Type_Bool,
			Value: leftR.Value.(float32) <= rightR.Value.(float32),
		}
	}
	panic("type error")
}

func NewLteSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &lteSyntax{
		kind:     2,
		priority: 50,
		left:     left,
		right:    right,
	}
}

// >
// gt syntax
type gtSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *gtSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *gtSyntax) Kind() int {
	return s.kind
}

func (s *gtSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *gtSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *gtSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *gtSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *gtSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *gtSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *gtSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	leftR := s.left.Evaluate(c)
	rightR := s.right.Evaluate(c)
	leftIfnerType := syntax.InferType(leftR.Value)
	rightInferType := syntax.InferType(rightR.Value)
	if leftIfnerType == syntax.Type_Number && leftIfnerType == rightInferType {
		return syntax.SyntaxValue{
			Type:  syntax.Type_Bool,
			Value: leftR.Value.(float32) > rightR.Value.(float32),
		}
	}
	panic("type error")
}

func NewGtSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &gtSyntax{
		kind:     2,
		priority: 50,
		left:     left,
		right:    right,
	}
}

// >=
// gte syntax
type gteSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *gteSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *gteSyntax) Kind() int {
	return s.kind
}

func (s *gteSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *gteSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *gteSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *gteSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *gteSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *gteSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *gteSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	leftR := s.left.Evaluate(c)
	rightR := s.right.Evaluate(c)
	leftIfnerType := syntax.InferType(leftR.Value)
	rightInferType := syntax.InferType(rightR.Value)
	if leftIfnerType == syntax.Type_Number && leftIfnerType == rightInferType {
		return syntax.SyntaxValue{
			Type:  syntax.Type_Bool,
			Value: leftR.Value.(float32) >= rightR.Value.(float32),
		}
	}
	panic("type error")
}

func NewGteSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &gteSyntax{
		kind:     2,
		priority: 50,
		left:     left,
		right:    right,
	}
}
