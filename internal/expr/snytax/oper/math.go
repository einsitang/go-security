package oper

import (
	"errors"

	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

// + add addition
type addSyntax struct {
	builtiOperSyntax
}

func (s *addSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *addSyntax) ReturnType() int {
	return syntax.Type_Number
}
func NewAddSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &addSyntax{
		builtiOperSyntax{
			kind:     2,
			priority: 35,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {
				return mathEvaluate(leftR, rightR, func(a, b int) int {
					return a + b
				}, func(a, b float32) float32 {
					return a + b
				})
			},
		},
	}
}

// - sub subtraction
type subSyntax struct {
	builtiOperSyntax
}

func (s *subSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *subSyntax) ReturnType() int {
	return syntax.Type_Number
}

func NewSubSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &subSyntax{
		builtiOperSyntax{
			kind:     2,
			priority: 35,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {
				return mathEvaluate(leftR, rightR, func(a, b int) int {
					return a - b
				}, func(a, b float32) float32 {
					return a - b
				})
			},
		},
	}
}

// * mul multiply
type mulSyntax struct {
	builtiOperSyntax
}

func (s *mulSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *mulSyntax) ReturnType() int {
	return syntax.Type_Number
}

func NewMulSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &mulSyntax{
		builtiOperSyntax{
			kind:     2,
			priority: 30,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {
				return mathEvaluate(leftR, rightR, func(a, b int) int {
					return a * b
				}, func(a, b float32) float32 {
					return a * b
				})
			},
		},
	}
}

// / div division
type divSyntax struct {
	builtiOperSyntax
}

func (s *divSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *divSyntax) ReturnType() int {
	return syntax.Type_Number
}

func NewDivSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &divSyntax{
		builtiOperSyntax{
			kind:     2,
			priority: 30,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {
				return mathEvaluate(leftR, rightR, func(a, b int) int {
					return a / b
				}, func(a, b float32) float32 {
					return a / b
				})
			},
		},
	}
}

// % mod modulo
type modSyntax struct {
	builtiOperSyntax
}

func (s *modSyntax) InputType() int {
	return syntax.Type_Number
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *modSyntax) ReturnType() int {
	return syntax.Type_Number
}

func NewModSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &modSyntax{
		builtiOperSyntax{
			kind:     2,
			priority: 30,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {
				return mathEvaluate(leftR, rightR, func(a, b int) int {
					return a % b
				}, func(a, b float32) float32 {
					panic("type error, modulo not support float number")
				})
			},
		},
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
	return syntax.SyntaxValue{
		Error:   errors.New("invalid types"),
		IsError: true,
	}
}
