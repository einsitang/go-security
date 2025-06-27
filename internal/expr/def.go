package expr

import (
	"errors"

	"github.com/bzick/tokenizer"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

type syntaxDef struct {

	// token
	Token *tokenizer.Token
	// 优先级
	Priority int

	// 参数数
	Kind int

	// 参数类型
	Type int
}

func buildSyntaxDef(token *tokenizer.Token) (*syntaxDef, error) {

	if expectType(token, []tokenizer.TokenKey{TComparison}) {
		// > >= == != < <=
		if token.ValueString() == "==" {
			return &syntaxDef{
				Token:    token,
				Priority: 55,
				Kind:     2,
				Type:     syntax.Type_String | syntax.Type_Number,
			}, nil
		}
		if token.ValueString() == "!=" {
			return &syntaxDef{
				Token:    token,
				Priority: 55,
				Kind:     2,
				Type:     syntax.Type_String | syntax.Type_Number,
			}, nil
		}
		return &syntaxDef{
			Token:    token,
			Priority: 50,
			Kind:     2,
			Type:     syntax.Type_Bool | syntax.Type_Number,
		}, nil
	} else if expectType(token, []tokenizer.TokenKey{TMath}) {
		// + -
		if token.ValueString() == "+" || token.ValueString() == "-" {
			return &syntaxDef{
				Token:    token,
				Priority: 35,
				Kind:     2,
				Type:     syntax.Type_Bool | syntax.Type_Number | syntax.Type_String,
			}, nil
		}
		// * / %
		return &syntaxDef{
			Token:    token,
			Priority: 30,
			Kind:     2,
			Type:     syntax.Type_Number,
		}, nil
	} else if expectType(token, []tokenizer.TokenKey{TLogic}) {
		// and or
		return &syntaxDef{
			Token:    token,
			Priority: 60,
			Kind:     2,
			Type:     syntax.Type_Bool,
		}, nil
	} else if expectType(token, []tokenizer.TokenKey{TNegate}) {
		return &syntaxDef{
			Token:    token,
			Priority: 20,
			Kind:     1,
			Type:     syntax.Type_Bool,
		}, nil
	}

	return nil, errors.New("invalid syntax")
}
