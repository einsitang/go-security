package oper

import (
	"fmt"

	"github.com/spf13/cast"

	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

type eqSyntax struct {
	builtiOperSyntax
}

func NewEqSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &eqSyntax{
		builtiOperSyntax{
			priority: 55,
			kind:     2,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {
				// 判定两者类型，比如字符串 '2' != 2 , 需要考虑隐性转型？
				// not eq 也存在相同问题
				lv := cast.ToString(leftR.Value)
				rv := cast.ToString(rightR.Value)
				return syntax.SyntaxValue{
					Type:  syntax.Type_Bool,
					Value: lv == rv,
				}
			},
		},
	}
}

// !=
// not equals syntax
type notEqSyntax struct {
	builtiOperSyntax
}

func NewNotEqSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &notEqSyntax{
		builtiOperSyntax{
			priority: 55,
			kind:     2,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {
				lv := cast.ToString(leftR.Value)
				rv := cast.ToString(rightR.Value)
				return syntax.SyntaxValue{
					Type:  syntax.Type_Bool,
					Value: lv != rv,
				}
			},
		},
	}
}

// <
// lt syntax
type ltSyntax struct {
	builtiOperSyntax
}

func NewLtSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &ltSyntax{
		builtiOperSyntax{
			priority: 50,
			kind:     2,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {

				leftIfnerType := syntax.InferType(leftR.Value)
				rightInferType := syntax.InferType(rightR.Value)
				if leftIfnerType == syntax.Type_Number && leftIfnerType == rightInferType {
					return syntax.SyntaxValue{
						Type:  syntax.Type_Bool,
						Value: cast.ToFloat32(leftR.Value) < cast.ToFloat32(rightR.Value),
					}
				}

				// 尝试转换成 float32
				if leftIfnerType == syntax.Type_String || rightInferType == syntax.Type_String {
					leftFloat32V, err := cast.ToFloat32E(leftR.Value)
					if err != nil {
						return syntax.SyntaxValue{
							Error:   err,
							IsError: true,
						}
					}
					rightFloat32V, err := cast.ToFloat32E(rightR.Value)
					if err != nil {
						return syntax.SyntaxValue{
							Error:   err,
							IsError: true,
						}
					}
					return syntax.SyntaxValue{
						Type:  syntax.Type_Bool,
						Value: leftFloat32V < rightFloat32V,
					}
				}

				// 左值不符合
				if leftIfnerType != syntax.Type_Number {
					return syntax.SyntaxValue{
						IsError: true,
						Error:   fmt.Errorf("expect number, but got \"%s\"", leftR.Value),
					}
				}

				// 右值不符合
				return syntax.SyntaxValue{
					IsError: true,
					Error:   fmt.Errorf("expect number, but got \"%s\"", rightR.Value),
				}
			},
		},
	}
}

// <=
// lte syntax
type lteSyntax struct {
	builtiOperSyntax
}

func NewLteSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &lteSyntax{
		builtiOperSyntax{
			priority: 50,
			kind:     2,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {

				leftIfnerType := syntax.InferType(leftR.Value)
				rightInferType := syntax.InferType(rightR.Value)
				if leftIfnerType == syntax.Type_Number && leftIfnerType == rightInferType {
					return syntax.SyntaxValue{
						Type:  syntax.Type_Bool,
						Value: cast.ToFloat32(leftR.Value) <= cast.ToFloat32(rightR.Value),
					}
				}

				// 尝试转换成 float32
				if leftIfnerType == syntax.Type_String || rightInferType == syntax.Type_String {
					leftFloat32V, err := cast.ToFloat32E(leftR.Value)
					if err != nil {
						return syntax.SyntaxValue{
							Error:   err,
							IsError: true,
						}
					}
					rightFloat32V, err := cast.ToFloat32E(rightR.Value)
					if err != nil {
						return syntax.SyntaxValue{
							Error:   err,
							IsError: true,
						}
					}
					return syntax.SyntaxValue{
						Type:  syntax.Type_Bool,
						Value: leftFloat32V <= rightFloat32V,
					}
				}

				// 左值不符合
				if leftIfnerType != syntax.Type_Number {
					return syntax.SyntaxValue{
						IsError: true,
						Error:   fmt.Errorf("expect number, but got \"%s\"", leftR.Value),
					}
				}

				// 右值不符合
				return syntax.SyntaxValue{
					IsError: true,
					Error:   fmt.Errorf("expect number, but got \"%s\"", rightR.Value),
				}
			},
		},
	}
}

// >
// gt syntax
type gtSyntax struct {
	builtiOperSyntax
}

func NewGtSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &gtSyntax{
		builtiOperSyntax{
			priority: 50,
			kind:     2,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {
				leftIfnerType := syntax.InferType(leftR.Value)
				rightInferType := syntax.InferType(rightR.Value)
				if leftIfnerType == syntax.Type_Number && leftIfnerType == rightInferType {
					return syntax.SyntaxValue{
						Type:  syntax.Type_Bool,
						Value: cast.ToFloat32(leftR.Value) > cast.ToFloat32(rightR.Value),
					}
				}

				// 尝试转换成 float32
				if leftIfnerType == syntax.Type_String || rightInferType == syntax.Type_String {
					leftFloat32V, err := cast.ToFloat32E(leftR.Value)
					if err != nil {
						return syntax.SyntaxValue{
							Error:   err,
							IsError: true,
						}
					}
					rightFloat32V, err := cast.ToFloat32E(rightR.Value)
					if err != nil {
						return syntax.SyntaxValue{
							Error:   err,
							IsError: true,
						}
					}
					return syntax.SyntaxValue{
						Type:  syntax.Type_Bool,
						Value: leftFloat32V > rightFloat32V,
					}
				}

				// 左值不符合
				if leftIfnerType != syntax.Type_Number {
					return syntax.SyntaxValue{
						IsError: true,
						Error:   fmt.Errorf("expect number, but got \"%s\"", leftR.Value),
					}
				}

				// 右值不符合
				return syntax.SyntaxValue{
					IsError: true,
					Error:   fmt.Errorf("expect number, but got \"%s\"", rightR.Value),
				}
			},
		},
	}
}

// >=
// gte syntax
type gteSyntax struct {
	builtiOperSyntax
}

func NewGteSyntax(left, right syntax.Syntax) syntax.Syntax {
	return &gteSyntax{
		builtiOperSyntax{
			priority: 50,
			kind:     2,
			left:     left,
			right:    right,
			evalute: func(leftR, rightR syntax.SyntaxValue) syntax.SyntaxValue {
				leftIfnerType := syntax.InferType(leftR.Value)
				rightInferType := syntax.InferType(rightR.Value)
				if leftIfnerType == syntax.Type_Number && leftIfnerType == rightInferType {
					return syntax.SyntaxValue{
						Type:  syntax.Type_Bool,
						Value: cast.ToFloat32(leftR.Value) >= cast.ToFloat32(rightR.Value),
					}
				}

				// 尝试转换成 float32
				if leftIfnerType == syntax.Type_String || rightInferType == syntax.Type_String {
					leftFloat32V, err := cast.ToFloat32E(leftR.Value)
					if err != nil {
						return syntax.SyntaxValue{
							Error:   err,
							IsError: true,
						}
					}
					rightFloat32V, err := cast.ToFloat32E(rightR.Value)
					if err != nil {
						return syntax.SyntaxValue{
							Error:   err,
							IsError: true,
						}
					}
					return syntax.SyntaxValue{
						Type:  syntax.Type_Bool,
						Value: leftFloat32V >= rightFloat32V,
					}
				}
				// 左值不符合
				if leftIfnerType != syntax.Type_Number {
					return syntax.SyntaxValue{
						IsError: true,
						Error:   fmt.Errorf("expect number, but got \"%s\"", leftR.Value),
					}
				}

				// 右值不符合
				return syntax.SyntaxValue{
					IsError: true,
					Error:   fmt.Errorf("expect number, but got \"%s\"", rightR.Value),
				}
			},
		},
	}
}
