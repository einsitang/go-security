package value

import (
	"github.com/einsitang/go-security/internal/expr/ctx"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

type paramSyntax struct {
	// 占位符 or 自定义参数
	isPlaceholder bool
	val           string
	priority      int
	kind          int
}

// 语句优先级
func (s *paramSyntax) Priority() int {
	return s.priority
}

// 入参个数
func (s *paramSyntax) Kind() int {
	return s.kind
}

func (s *paramSyntax) InputType() int {
	return syntax.Type_String
}

// 出参类型
func (s *paramSyntax) ReturnType() int {
	return syntax.Type_String | syntax.Type_Number
}

// Left,Right 左右值入参
func (s *paramSyntax) Left() syntax.Syntax {
	panic("Syntax not support left value")
}

func (s *paramSyntax) Right() syntax.Syntax {
	panic("Syntax not support right value")
}

func (s *paramSyntax) ChangeLeft(left syntax.Syntax) {
	panic("Syntax not support left value")
}

func (s *paramSyntax) ChangeRight(right syntax.Syntax) {
	panic("Syntax not support right value")
}

// 运行求值
func (s *paramSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {

	var v any
	if s.isPlaceholder {
		v = c.Params[s.val]
	} else {
		v = c.CustomParams[s.val]
	}

	return syntax.SyntaxValue{
		Type:    syntax.InferType(v),
		Value:   v,
		IsError: false,
	}
}

func NewParamSyntax(val string, isPlaceholder bool) syntax.Syntax {
	return &paramSyntax{
		isPlaceholder: isPlaceholder,
		val:           val,
		kind:          0,
		priority:      100,
	}
}
