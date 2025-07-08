package expr

import (
	"fmt"
	"slices"
	"strings"

	"github.com/bzick/tokenizer"
	syntax "github.com/einsitang/go-security/internal/expr/snytax"
	"github.com/einsitang/go-security/internal/expr/snytax/oper"
	"github.com/einsitang/go-security/internal/expr/snytax/value"
)

// define custom tokens keys
const (
	TComparison tokenizer.TokenKey = iota + 1
	TDot
	TMath
	TDoubleQuoted
	TSignleQuoted
	TPolicy
	TBuiltinFunction
	TLogic
	TNegate
	TCurlyOpen
	TCurlyClose
	TPlaceholder
	TCustomParam
	TComma
)

type syntaxAnalyzer struct {
	lexer *tokenizer.Tokenizer
}

type SyntaxTree struct {
	Policy string
	Syntax syntax.Syntax
}

type SyntaxAnalyzer interface {
	Parse(input string) (*SyntaxTree, error)
}

func NewAnalyzer() *syntaxAnalyzer {

	_tokenizer := tokenizer.New()
	_tokenizer.DefineTokens(TPolicy, []string{"allow", "deny"}) // Policy
	_tokenizer.DefineTokens(TBuiltinFunction, []string{
		"Role", "Permission", "Group", "Roles", "Permissions", "Groups",
	}, tokenizer.AloneTokenOption) // 内置单元函数
	_tokenizer.DefineTokens(TCurlyOpen, []string{"("})
	_tokenizer.DefineTokens(TCurlyClose, []string{")"})
	_tokenizer.DefineTokens(TNegate, []string{"!"})                                  // 逻辑运算符 单元
	_tokenizer.DefineTokens(TMath, []string{"+", "-", "/", "*", "%"})                // 运算符 双元
	_tokenizer.DefineTokens(TComparison, []string{"<", "<=", ">=", ">", "==", "!="}) // 逻辑运算符 双元
	_tokenizer.DefineTokens(TLogic, []string{"and", "or"})                           // 逻辑符 双元
	_tokenizer.DefineTokens(TDot, []string{"."})
	_tokenizer.DefineTokens(TComma, []string{","})
	_tokenizer.DefineStringToken(TDoubleQuoted, `"`, `"`)
	_tokenizer.DefineStringToken(TSignleQuoted, `'`, `'`)
	_tokenizer.DefineTokens(TPlaceholder, []string{"$"})
	_tokenizer.DefineTokens(TCustomParam, []string{"#"})
	_tokenizer.AllowKeywordSymbols(tokenizer.Underscore, tokenizer.Numbers)

	return &syntaxAnalyzer{
		lexer: _tokenizer,
	}

}

func (analyzer *syntaxAnalyzer) Parse(input string) (*SyntaxTree, error) {

	stream := analyzer.lexer.ParseString(input)
	defer stream.Close()

	var policy string
	if stream.IsValid() {
		token := stream.CurrentToken()
		if expectType(token, []tokenizer.TokenKey{TPolicy}) {
			// 标记 allow or deny => ast.Strategy = ?
			policy = token.ValueString()
			next := stream.GoNext()
			if !next.IsValid() {
				// 结束
				return &SyntaxTree{
					Policy: policy,
				}, nil
			}
			if !expectStringValue(next.CurrentToken(), []string{":"}) {
				// 出错了,如果有后续必须是:
				return nil, fmt.Errorf("\"%s\" expect next token must \":\" or EOF", token.ValueString())
			}
			stream.GoNext()
			_syntax, err := parseWithScope(stream, 0, input)
			if err != nil {
				return nil, err
			}
			return &SyntaxTree{Policy: policy, Syntax: _syntax}, nil
		}

		return nil, parseError("express must begin with \"Policy\" like: `allow:` or `deny:` ", token, stream, input)
	}
	return nil, parseError("there are some errors with express", stream.CurrentToken(), stream, input)
}

func parseWithScope(stream *tokenizer.Stream, scope int, input string) (syntax.Syntax, error) {
	// 子句 statementStack
	syntaxStatementStack := []syntax.Syntax{}
	// syntax def
	cacheOperTokens := []*syntaxDef{}

	for stream.IsValid() {
		token := stream.CurrentToken()
		// fmt.Printf("[DEBUG] %d:%d %s \n", token.Line(), token.Offset(), token.ValueString())

		// 括号开辟新空间
		// (
		if expectType(token, []tokenizer.TokenKey{TCurlyOpen}) {
			// (
			stream.GoNext()
			s, err := parseWithScope(stream, scope+1, input)
			if err != nil {
				return nil, err
			}
			syntaxStatementStack = append(syntaxStatementStack, s)
		} else if expectType(token, []tokenizer.TokenKey{TCurlyClose}) {
			// )
			if scope == 0 {
				return nil, parseError("没有找到 \"(\" , 无法解析 \")\"", token, stream, input)
			}
			// 结束，合并语法树，跳出当前循环

			// stream to next
			// stream.GoNext()
			break

		} else if expectValueToken(token) {
			// 值语法处理
			_syntax, err := valueSyntaxParse(token, stream, input)
			if err != nil {
				return nil, err
			}

			syntaxStatementStack = append(syntaxStatementStack, _syntax)
		} else {
			// 操作语法处理
			// > >= == != < <= +-*/% and or !
			tokenDef, err := buildSyntaxDef(token)
			if err != nil {
				return nil, parseError(err.Error(), token, stream, input)
			}
			cacheOperTokens = append(cacheOperTokens, tokenDef)
		}
		stream.GoNext()
	}
	// 聚合解析 cacheOperTokens 与 syntaxStatementStack
	return mergeAnalysis(cacheOperTokens, syntaxStatementStack, stream, input)
}

func pickPriorityOperToken(cacheOperTokens []*syntaxDef) (int, *syntaxDef) {
	var operTokenPosition int
	var currentOperToken *syntaxDef
	for i, tokenDef := range cacheOperTokens {
		if currentOperToken == nil {
			currentOperToken = tokenDef
			operTokenPosition = i
		} else {
			if currentOperToken.Priority > tokenDef.Priority {
				currentOperToken = tokenDef
				operTokenPosition = i
			}
		}
	}
	return operTokenPosition, currentOperToken
}
func mergeAnalysis(cacheOperTokens []*syntaxDef, syntaxStatementStack []syntax.Syntax, stream *tokenizer.Stream, input string) (syntax.Syntax, error) {

	for len(cacheOperTokens) > 0 {
		operPosition, operToken := pickPriorityOperToken(cacheOperTokens)

		_syntax, err := operSyntaxParse(operToken.Token, stream, input)
		if err != nil {
			return nil, err
		}

		switch operToken.Kind {
		case 1:
			// 单元
			v := syntaxStatementStack[operPosition]
			if v.ReturnType()&_syntax.InputType() == 0 {
				return nil, parseError("mismatched types", operToken.Token, stream, input)
			}
			_syntax.ChangeLeft(v)

			syntaxStatementStack[operPosition] = _syntax

		case 2:
			// 双元
			left := syntaxStatementStack[operPosition]
			right := syntaxStatementStack[operPosition+1]
			if left.ReturnType()&right.ReturnType()&_syntax.InputType() == 0 {
				return nil, parseError("mismatched types", operToken.Token, stream, input)
			}
			_syntax.ChangeLeft(left)
			_syntax.ChangeRight(right)
			_n := append(syntaxStatementStack[:operPosition], _syntax)
			_n = append(_n, syntaxStatementStack[operPosition+2:]...)
			syntaxStatementStack = _n
		}
		cacheOperTokens = append(cacheOperTokens[:operPosition], cacheOperTokens[operPosition+1:]...)
	}

	return syntaxStatementStack[0], nil

}

// 内置函数语法解析器
func builtinFunctionParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) (syntax.Syntax, error) {

	switch token.ValueString() {
	case "Role", "Permission", "Group":
		return singleVarBuiltinFunctionParse(token, stream, input)
	case "Roles", "Permissions", "Groups":
		return multiVarBuiltinFunctionParse(token, stream, input)
	}

	return nil, parseError("unknow builtin function", token, stream, input)
}

func arrayParamsParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) ([]string, error) {
	values := []string{}
	curlyOpen := stream.GoNext().CurrentToken()
	// must with (
	if !expectType(curlyOpen, []tokenizer.TokenKey{TCurlyOpen}) {
		return nil, parseError(fmt.Sprintf("syntax error, %s must with \"(\"", token.ValueString()), token, stream, input)
	}

	// Looking forward to the comma ?
	lookForComma := false
	nextToken := stream.GoNext().CurrentToken()
	for nextToken.IsValid() {

		if !lookForComma && expectType(nextToken, []tokenizer.TokenKey{tokenizer.TokenString}) {
			// String Constant
			lookForComma = true
			val := nextToken.ValueString()
			val = strings.Trim(val, "'")
			val = strings.Trim(val, "\"")
			values = append(values, val)
		} else if lookForComma && expectType(nextToken, []tokenizer.TokenKey{TComma}) {
			// comma
			lookForComma = false
		} else {
			// 括号结束
			break
		}
		nextToken = stream.GoNext().CurrentToken()
	}

	curlyClose := stream.CurrentToken()
	// must with )
	if !expectType(curlyClose, []tokenizer.TokenKey{TCurlyClose}) {
		return nil, parseError(fmt.Sprintf("syntax error, %s must with \")\" but meet \"%s\"", token.ValueString(), curlyClose.ValueString()), token, stream, input)
	}

	if len(values) == 0 {
		return nil, parseError(fmt.Sprintf("syntax error, %s must with at least one value", token.ValueString()), token, stream, input)
	}

	return values, nil
}

func multiVarBuiltinFunctionParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) (syntax.Syntax, error) {

	values, err := arrayParamsParse(token, stream, input)
	if err != nil {
		return nil, err
	}

	// after expect check
	nextToken := stream.NextToken()
	if nextToken.IsValid() && !expectStringValue(nextToken, []string{"and", "or", ")"}) {
		return nil, parseError(fmt.Sprintf("%s(%s)\" %s only supports \"and\" and \"or\" constructions.\n", token.ValueString(), values, nextToken.ValueString()), token, stream, input)
	}

	tokenString := token.ValueString()
	switch tokenString {
	case "Roles":
		return value.NewRolesSyntax(values), nil
	case "Permissions":
		return value.NewPermissionsSyntax(values), nil
	case "Groups":
		return value.NewGroupsSyntax(values), nil
	}

	return nil, parseError("unknow builtin function", token, stream, input)
}

// Role Permission Group
func singleVarBuiltinFunctionParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) (syntax.Syntax, error) {
	curlyOpen := stream.GoNext().CurrentToken()
	// must with (
	if !expectType(curlyOpen, []tokenizer.TokenKey{TCurlyOpen}) {
		return nil, parseError(fmt.Sprintf("syntax error, %s must with \"(\"", token.ValueString()), token, stream, input)
	}

	vToken := stream.GoNext().CurrentToken()
	val := vToken.ValueString()
	val = strings.Trim(val, "'")
	val = strings.Trim(val, "\"")
	// must with StringConstant
	if !expectType(vToken, []tokenizer.TokenKey{tokenizer.TokenString}) {
		return nil, parseError(fmt.Sprintf("grammatical error, you need input string. example: %s(\"something\")\n", token.ValueString()), token, stream, input)
	}

	curlyClose := stream.GoNext().CurrentToken()
	// must with )
	if !expectType(curlyClose, []tokenizer.TokenKey{TCurlyClose}) {
		return nil, parseError(fmt.Sprintf("syntax error, %s must with \")\"\n", vToken.ValueString()), token, stream, input)
	}

	// after expect check
	nextToken := stream.NextToken()
	if nextToken.IsValid() && !expectStringValue(nextToken, []string{"and", "or", ")"}) {
		return nil, parseError(fmt.Sprintf("%s(%s)\" %s only supports \"and\" and \"or\" constructions.\n", token.ValueString(), vToken.ValueString(), nextToken.ValueString()), token, stream, input)
	}

	tokenString := token.ValueString()
	switch tokenString {
	case "Role":
		return value.NewRoleSyntax(val), nil
	case "Permission":
		return value.NewPermissionSyntax(val), nil
	case "Group":
		return value.NewGroupSyntax(val), nil
	}

	return nil, parseError("unknow builtin function", token, stream, input)
}

// 占位符变量解析器
func placeholderSyntaxParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) (syntax.Syntax, error) {
	strToken := stream.GoNext().CurrentToken()
	if expectType(strToken, []tokenizer.TokenKey{tokenizer.TokenKeyword}) {
		return value.NewParamSyntax(strToken.ValueString(), true), nil
	}
	return nil, parseError("错误变量表达式", token, stream, input)
}

// 自定义变量解析器
func customParamSyntaxParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) (syntax.Syntax, error) {
	strToken := stream.GoNext().CurrentToken()
	if expectType(strToken, []tokenizer.TokenKey{tokenizer.TokenKeyword}) {
		return value.NewParamSyntax(strToken.ValueString(), false), nil
	}
	return nil, parseError("错误变量表达式", token, stream, input)
}

// 字符串常量解析器
func constantSyntaxParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) (syntax.Syntax, error) {
	switch token.Key() {
	case tokenizer.TokenString:
		val := token.ValueString()
		val = strings.Trim(val, "'")
		val = strings.Trim(val, "\"")
		return value.NewConstantSyntax(val), nil
	case tokenizer.TokenInteger:
		return value.NewConstantSyntax(token.ValueInt64()), nil
	case tokenizer.TokenFloat:
		return value.NewConstantSyntax(token.ValueFloat64()), nil
	}

	return nil, parseError("错误常量表达式,目前仅支持 字符串 / 数字 / 布尔 常量", token, stream, input)
}

// 值语句解析
func valueSyntaxParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) (syntax.Syntax, error) {
	if expectType(token, []tokenizer.TokenKey{tokenizer.TokenString, tokenizer.TokenInteger, tokenizer.TokenFloat}) {
		// Constant[String|Number] / Param
		return constantSyntaxParse(token, stream, input)
	} else if expectType(token, []tokenizer.TokenKey{TPlaceholder}) {
		return placeholderSyntaxParse(token, stream, input)
	} else if expectType(token, []tokenizer.TokenKey{TCustomParam}) {
		return customParamSyntaxParse(token, stream, input)
	} else if expectType(token, []tokenizer.TokenKey{TBuiltinFunction}) {
		// Role/Permission/Group
		return builtinFunctionParse(token, stream, input)
	}

	return nil, parseError("unknow value syntax", token, stream, input)
}

// 操作语句解析
func operSyntaxParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) (syntax.Syntax, error) {
	switch token.ValueString() {
	case "+":
		return oper.NewAddSyntax(nil, nil), nil
	case "-":
		return oper.NewSubSyntax(nil, nil), nil
	case "*":
		return oper.NewMulSyntax(nil, nil), nil
	case "/":
		return oper.NewDivSyntax(nil, nil), nil
	case "%":
		return oper.NewModSyntax(nil, nil), nil
	case "==":
		return oper.NewEqSyntax(nil, nil), nil
	case "!=":
		return oper.NewNotEqSyntax(nil, nil), nil
	case ">":
		return oper.NewGtSyntax(nil, nil), nil
	case ">=":
		return oper.NewGteSyntax(nil, nil), nil
	case "<":
		return oper.NewLtSyntax(nil, nil), nil
	case "<=":
		return oper.NewLteSyntax(nil, nil), nil
	case "and":
		return oper.NewAndSyntax(nil, nil), nil
	case "or":
		return oper.NewOrSyntax(nil, nil), nil
	case "!":
		return oper.NewNegateSyntax(nil), nil
	}

	return nil, parseError("unknow oper syntax", token, stream, input)
}

// expectValueToken
// 检查当前token值 是否属于 "值Token" (ValueToken)
func expectValueToken(token *tokenizer.Token) bool {
	switch token.Key() {
	case TBuiltinFunction, tokenizer.TokenString, TPlaceholder, TCustomParam, tokenizer.TokenFloat, tokenizer.TokenInteger:
		return true
	}

	return false
}

// expectType
// 检测当前token的类型
func expectType(token *tokenizer.Token, types []tokenizer.TokenKey) bool {
	return token.IsValid() && slices.Contains(types, token.Key())
}

// expectStringValue
// 检测当前token的值(必须为字符串)
func expectStringValue(token *tokenizer.Token, values []string) bool {
	return token.IsValid() && slices.Contains(values, token.ValueString())
}

// DEBUG 用
func (l *syntaxAnalyzer) DebugTokens(input string) {
	stream := l.lexer.ParseString(input)
	defer stream.Close()
	for stream.IsValid() {
		token := stream.CurrentToken()
		fmt.Printf("token[ %d:%d ]: %-10s type: %v isKeyword: %v \n", token.Line(), token.Offset(), token.Value(), token.Key(), token.IsKeyword())
		stream.GoNext()
	}

}

func parseError(msg string, token *tokenizer.Token, stream *tokenizer.Stream, input string) error {
	limitLen := len(input)
	if limitLen > token.Offset()+25 {
		limitLen = token.Offset() + 25
	}
	before := input[:token.Offset()]
	after := input[token.Offset():limitLen]
	errorContext := input
	tipsLine := tipsLine(len(before), len(after))
	return fmt.Errorf("[%d:%d] \"%s\": %s\n%s\n%s", token.Line(), token.Offset(), token.ValueString(), msg, errorContext, tipsLine)
}

func tipsLine(offset int, after int) string {
	line := ""
	for i := 0; i < offset; i++ {
		line += "-"
	}
	line += "^"
	for i := 0; i < after; i++ {
		line += "-"
	}
	return line
}
