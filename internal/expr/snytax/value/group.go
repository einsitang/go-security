package value

import (
	"slices"

	"github.com/einsitang/go-security/internal/expr/ctx"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

// Group("...")
type groupSyntax struct {
	val      string
	priority int
	kind     int
}

// 语句优先级
func (s *groupSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *groupSyntax) Kind() int {
	return s.kind
}

func (s *groupSyntax) InputType() int {
	return syntax.Type_String
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *groupSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *groupSyntax) Left() syntax.Syntax {
	panic("Syntax not support left value")
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *groupSyntax) Right() syntax.Syntax {
	panic("Syntax not support right value")
}

// 改变 一元 双元(左) 参数
func (s *groupSyntax) ChangeLeft(left syntax.Syntax) {
	panic("Syntax not support left value")
}

// 改变 双元 右参数
func (s *groupSyntax) ChangeRight(right syntax.Syntax) {
	panic("Syntax not support right value")
}

// 运行求值
func (s *groupSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	return syntax.SyntaxValue{
		Type:    syntax.Type_Bool,
		Value:   slices.Contains(c.Principal.Groups(), s.val),
		IsError: false,
	}
}

func NewGroupSyntax(val string) syntax.Syntax {
	return &groupSyntax{
		val:      val,
		kind:     0,
		priority: 100,
	}
}

// Groups
type groupsSyntax struct {
	val      []string
	priority int
	kind     int
}

// 语句优先级
func (s *groupsSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *groupsSyntax) Kind() int {
	return s.kind
}

// 入参类型要求
func (s *groupsSyntax) InputType() int {
	return syntax.Type_String
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *groupsSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *groupsSyntax) Left() syntax.Syntax {
	panic("Syntax not support left value")
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *groupsSyntax) Right() syntax.Syntax {
	panic("Syntax not support right value")
}

// 改变 一元 双元(左) 参数
func (s *groupsSyntax) ChangeLeft(left syntax.Syntax) {
	panic("Syntax not support left value")
}

// 改变 双元 右参数
func (s *groupsSyntax) ChangeRight(right syntax.Syntax) {
	panic("Syntax not support right value")
}

// 运行求值
func (s *groupsSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	v := false
	for _, g := range c.Principal.Groups() {
		if slices.Contains(s.val, g) {
			v = true
			break
		}
	}
	return syntax.SyntaxValue{
		Type:    syntax.Type_Bool,
		Value:   v,
		IsError: false,
	}
}

func NewGroupsSyntax(val []string) syntax.Syntax {
	return &groupsSyntax{
		val:      val,
		kind:     0,
		priority: 100,
	}
}
