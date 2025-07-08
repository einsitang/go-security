package value

import (
	"github.com/einsitang/go-security/internal/expr/ctx"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

type constantSyntax struct {
	val      any
	priority int
	kind     int
}

func (s *constantSyntax) Priority() int {
	return s.priority
}

func (s *constantSyntax) Kind() int {
	return s.kind
}

func (s *constantSyntax) InputType() int {
	return syntax.Type_String | syntax.Type_Number | syntax.Type_Bool
}

func (s *constantSyntax) ReturnType() int {
	return syntax.InferType(s.val)
}

func (s *constantSyntax) Left() syntax.Syntax {
	panic("Syntax not support left value")
}

func (s *constantSyntax) Right() syntax.Syntax {
	panic("Syntax not support right value")
}

func (s *constantSyntax) ChangeLeft(left syntax.Syntax) {
	panic("Syntax not support left value")
}

func (s *constantSyntax) ChangeRight(right syntax.Syntax) {
	panic("Syntax not support right value")
}

// 运行求值
func (s *constantSyntax) Evaluate(c *ctx.Context) syntax.SyntaxValue {
	t := syntax.InferType(s.val)
	return syntax.SyntaxValue{
		Type:    t,
		Value:   s.val,
		IsError: false,
	}
}

func NewConstantSyntax(val any) syntax.Syntax {
	switch val := val.(type) {
	case string:
		return &constantSyntax{
			val:      val,
			priority: 100,
			kind:     0,
		}
	case int, int32, int64:
		return &constantSyntax{
			val:      int(val.(int64)),
			priority: 100,
			kind:     0,
		}
	case float64, float32:
		return &constantSyntax{
			val:      val.(float32),
			priority: 100,
			kind:     0,
		}
	case bool:
		return &constantSyntax{
			val:      val,
			priority: 100,
			kind:     0,
		}
	}
	panic("unknow value type")
}
