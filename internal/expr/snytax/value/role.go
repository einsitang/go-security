package value

import (
	"slices"
	"strings"

	"github.com/einsitang/go-security/internal/expr/ctx"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

// Role("...")
type roleSyntax struct {
	val      string
	priority int
	kind     int
}

// 语句优先级
func (s *roleSyntax) Priority() int {
	return s.priority
}

// 操作符支持参数个数 一元操作符为1，二元操作符为2
func (s *roleSyntax) Kind() int {
	return s.kind
}

func (s *roleSyntax) InputType() int {
	return syntax.Type_String
}

// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
func (s *roleSyntax) ReturnType() int {
	return syntax.Type_Bool
}

// 获取语句内的左操作数
// 如果是 一元 Kind == 1 , 则左操作数为单操作数
func (s *roleSyntax) Left() syntax.Syntax {
	panic("Syntax not support left value")
}

// 获取语句内的右操作数
// 如果非 二元 Kind !=2 , 则取Right值will panic
func (s *roleSyntax) Right() syntax.Syntax {
	panic("Syntax not support right value")
}

// 改变 一元 双元(左) 参数
func (s *roleSyntax) ChangeLeft(left syntax.Syntax) {
	panic("Syntax not support left value")
}

// 改变 双元 右参数
func (s *roleSyntax) ChangeRight(right syntax.Syntax) {
	panic("Syntax not support right value")
}

// 运行求值
func (s *roleSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	return syntax.SyntaxValue{
		Type:    syntax.Type_Bool,
		Value:   slices.Contains(c.Principal.Roles(), s.val),
		IsError: false,
	}
}

func NewRoleSyntax(val string) syntax.Syntax {
	value := strings.Trim(val, "'")
	value = strings.Trim(value, "\"")
	return &roleSyntax{
		val:      value,
		kind:     0,
		priority: 100,
	}
}
