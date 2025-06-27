package oper

import (
	"github.com/einsitang/go-security/internal/expr/ctx"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

// + add addition
type addSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *addSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *addSyntax) Kind() int {
	return s.kind
}

func (s *addSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *addSyntax) ReturnType() int {
	return syntax.Type_Number
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *addSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *addSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *addSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *addSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *addSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	leftR := s.left.Evaluate(c)
	rightR := s.right.Evaluate(c)
	return mathEvaluate(leftR, rightR, func(a, b int) int {
		return a + b
	}, func(a, b float32) float32 {
		return a + b
	})
}

func NewAddSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &addSyntax{
		priority: 35,
		kind:     2,
		left:     left,
		right:    right,
	}
}

// - sub subtraction
type subSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *subSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *subSyntax) Kind() int {
	return s.kind
}

func (s *subSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *subSyntax) ReturnType() int {
	return syntax.Type_Number
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *subSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *subSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *subSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *subSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *subSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	leftR := s.left.Evaluate(c)
	rightR := s.right.Evaluate(c)
	return mathEvaluate(leftR, rightR, func(a, b int) int {
		return a - b
	}, func(a, b float32) float32 {
		return a - b
	})
}

func NewSubSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &subSyntax{
		priority: 35,
		kind:     2,
		left:     left,
		right:    right,
	}
}

// * mul multiply
type mulSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *mulSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *mulSyntax) Kind() int {
	return s.kind
}

func (s *mulSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *mulSyntax) ReturnType() int {
	return syntax.Type_Number
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *mulSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *mulSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *mulSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *mulSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *mulSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	leftR := s.left.Evaluate(c)
	rightR := s.right.Evaluate(c)
	return mathEvaluate(leftR, rightR, func(a, b int) int {
		return a * b
	}, func(a, b float32) float32 {
		return a * b
	})
}

func NewMulSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &mulSyntax{
		priority: 30,
		kind:     2,
		left:     left,
		right:    right,
	}
}

// / div division
type divSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *divSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *divSyntax) Kind() int {
	return s.kind
}

func (s *divSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *divSyntax) ReturnType() int {
	return syntax.Type_Number
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *divSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *divSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *divSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *divSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *divSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	leftR := s.left.Evaluate(c)
	rightR := s.right.Evaluate(c)
	return mathEvaluate(leftR, rightR, func(a, b int) int {
		return a / b
	}, func(a, b float32) float32 {
		return a / b
	})
}

func NewDivSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &divSyntax{
		priority: 30,
		kind:     2,
		left:     left,
		right:    right,
	}
}

// % mod modulo
type modSyntax struct {
	priority    int
	kind        int
	left, right syntax.Syntax
}

// 语句优先级
func (s *modSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *modSyntax) Kind() int {
	return s.kind
}

func (s *modSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *modSyntax) ReturnType() int {
	return syntax.Type_Number
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *modSyntax) Left() syntax.Syntax {
	return s.left
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *modSyntax) Right() syntax.Syntax {
	return s.right
}

// 改变 一元 双元(左) 参数
func (s *modSyntax) ChangeLeft(left syntax.Syntax) {
	s.left = left
}

// 改变 双元 右参数
func (s *modSyntax) ChangeRight(right syntax.Syntax) {
	s.right = right
}

// 运行求值
func (s *modSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	leftR := s.left.Evaluate(c)
	rightR := s.right.Evaluate(c)
	return mathEvaluate(leftR, rightR, func(a, b int) int {
		return a % b
	}, func(a, b float32) float32 {
		panic("type error, modulo not support float number")
	})
}

func NewModSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &modSyntax{
		priority: 30,
		kind:     2,
		left:     left,
		right:    right,
	}
}

type intFn func(a, b int) int
type floatFn func(a, b float32) float32

func mathEvaluate(lr, rr syntax.SyntaxValue, iCallback intFn, fCallback floatFn) syntax.SyntaxValue {
	leftIfnerType := syntax.InferType(lr.Value)
	rightInferType := syntax.InferType(rr.Value)
	if leftIfnerType == syntax.Type_Number && leftIfnerType == rightInferType {
		// 具体值
		switch lr.Value.(type) {
		case int:
			return syntax.SyntaxValue{
				Type:  syntax.Type_Number,
				Value: iCallback(lr.Value.(int), rr.Value.(int)),
			}
		case float32:
			return syntax.SyntaxValue{
				Type:  syntax.Type_Number,
				Value: fCallback(lr.Value.(float32), rr.Value.(float32)),
			}
		}
	}
	panic("type error")
}
