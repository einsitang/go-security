package syntax

import "github.com/einsitang/go-security/internal/expr/ctx"

const (
	Type_Bool = 1 << iota
	Type_Number
	Type_String
)

type SyntaxValue struct {
	Type  int
	Value any
}

type Syntax interface {

	// 语句优先级
	Priority() int

	// 操作符支持参数个数 一元操作符为1，二元操作符为2
	Kind() int

	// 入参类型要求
	InputType() int

	// 支持的出参类型,具体结果得执行 Evaluate 运行后得出
	ReturnType() int

	// 获取语句内的左操作数
	// 如果是 一元 Kind == 1 , 则左操作数为单操作数
	Left() Syntax
	// 获取语句内的右操作数
	// 如果非 二元 Kind !=2 , 则取Right值will panic
	Right() Syntax

	// 改变 一元 双元(左) 参数
	ChangeLeft(left Syntax)
	// 改变 双元 右参数
	ChangeRight(right Syntax)

	// 运行求值
	Evaluate(c *ctx.Context) SyntaxValue
}

// 推断值类型
func InferType(val any) int {
	t := Type_String
	switch val.(type) {
	case string:
		t = Type_String
	case int, int64, float32, float64:
		t = Type_Number
	case bool:
		t = Type_Bool
	}
	return t
}
