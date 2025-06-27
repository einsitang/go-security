package expr

import (
	"fmt"
	"slices"

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
	TRole
	TPermission
	TGroup
	TLogic
	TNegate
	TCurlyOpen
	TCurlyClose
	TPlaceholder
)

type syntaxAnalyzer struct {
	lexer *tokenizer.Tokenizer
	input string
}

type SyntaxTree struct {
	Policy string
	Syntax syntax.Syntax
}

type SyntaxAnalyzer interface {
	Parse(input string) *SyntaxTree
}

func NewAnalyzer() *syntaxAnalyzer {

	_tokenizer := tokenizer.New()
	_tokenizer.DefineTokens(TPolicy, []string{"allow", "deny", "skip"}) // Policy
	_tokenizer.DefineTokens(TRole, []string{"Role"})                    // 内置单元函数
	_tokenizer.DefineTokens(TPermission, []string{"Permission"})        // 内置单元函数
	_tokenizer.DefineTokens(TGroup, []string{"Group"})                  // 内置单元函数
	_tokenizer.DefineTokens(TCurlyOpen, []string{"("})
	_tokenizer.DefineTokens(TCurlyClose, []string{")"})
	_tokenizer.DefineTokens(TNegate, []string{"!"})                                  // 逻辑运算符 单元
	_tokenizer.DefineTokens(TMath, []string{"+", "-", "/", "*", "%"})                // 运算符 双元
	_tokenizer.DefineTokens(TComparison, []string{"<", "<=", ">=", ">", "==", "!="}) // 逻辑运算符 双元
	_tokenizer.DefineTokens(TLogic, []string{"and", "or"})                           // 逻辑符 双元
	_tokenizer.DefineTokens(TDot, []string{"."})
	_tokenizer.DefineStringToken(TDoubleQuoted, `"`, `"`)
	_tokenizer.DefineStringToken(TSignleQuoted, `'`, `'`)
	_tokenizer.DefineTokens(TPlaceholder, []string{"$"})
	_tokenizer.AllowKeywordSymbols(tokenizer.Underscore, tokenizer.Numbers)

	return &syntaxAnalyzer{
		lexer: _tokenizer,
	}

}

func (analyzer *syntaxAnalyzer) Parse(input string) *SyntaxTree {

	stream := analyzer.lexer.ParseString(input)
	analyzer.input = input
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
				}
			}
			if !expectStringValue(next.CurrentToken(), []string{":"}) {
				// 出错了,如果有后续必须是:
				panic(fmt.Errorf("\"%s\" expect next token must \":\" or EOF", token.ValueString()))
			}
			stream.GoNext()
			_syntax := parseWithScope(stream, 0, input)
			return &SyntaxTree{Policy: policy, Syntax: _syntax}
		}
	}
	panic("解析出错")
}

func parseWithScope(stream *tokenizer.Stream, scope int, input string) syntax.Syntax {
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
			syntaxStatementStack = append(syntaxStatementStack, parseWithScope(stream, scope+1, input))
		} else if expectType(token, []tokenizer.TokenKey{TCurlyClose}) {
			// )
			if scope == 0 {
				parsePanic("没有找到 \"(\" , 无法解析 \")\"", token, stream, input)
			}
			// 结束，合并语法树，跳出当前循环

			// stream to next
			// stream.GoNext()
			break

		} else if expectValueToken(token) {
			// 值语法处理
			_syntax := valueSyntaxParse(token, stream, input)
			syntaxStatementStack = append(syntaxStatementStack, _syntax)
		} else {
			// 操作语法处理
			// > >= == != < <= +-*/% and or
			tokenDef, err := buildSyntaxDef(token)
			if err != nil {
				parsePanic(err.Error(), token, stream, input)
				return nil
			}
			cacheOperTokens = append(cacheOperTokens, tokenDef)

			// negate 补丁，因为 negate 需要确保取右值，如果按照原来的逻辑很有可能把左值赋给negate
			if token.Key() == TNegate {
				if !stream.NextToken().IsValid() {
					parsePanic("! syntax without value", token, stream, input)
					return nil
				}
				stream.GoNext()
				continue
			}

		}

		cacheOperTokens, syntaxStatementStack = mergeSyntax(cacheOperTokens, syntaxStatementStack, stream, input)
		stream.GoNext()
	}

	// 结束还有？再做一次计算
	if len(cacheOperTokens) > 0 {
		cacheOperTokens, syntaxStatementStack = mergeSyntax(cacheOperTokens, syntaxStatementStack, stream, input)
	}
	if len(cacheOperTokens) == 0 && len(syntaxStatementStack) == 1 {
		return syntaxStatementStack[0]
	}
	parsePanic("incorrect expression", cacheOperTokens[0].Token, stream, input)
	return nil
}

func mergeSyntax(cacheOperTokens []*syntaxDef, syntaxStatementStack []syntax.Syntax, stream *tokenizer.Stream, input string) ([]*syntaxDef, []syntax.Syntax) {
	for len(cacheOperTokens) != 0 {
		// 尝试计算 cacheOperToken
		cacheOperToken := cacheOperTokens[len(cacheOperTokens)-1]

		// 解析 cacheOperToken 检查 语法的值数量要求
		if cacheOperToken.Kind > len(syntaxStatementStack) {
			return cacheOperTokens, syntaxStatementStack
		}
		// 根据值数量从 syntaxStatemens 中获取最近(最后)入栈的语句
		// 检查 cacheOperToken 与 语句(参数) 返回值是否一致
		checkType := cacheOperToken.Type
		syntaxArgs := syntaxStatementStack[len(syntaxStatementStack)-cacheOperToken.Kind:]
		for _, syntaxArg := range syntaxArgs {
			checkType &= syntaxArg.ReturnType()

		}
		if checkType == 0 {
			return cacheOperTokens, syntaxStatementStack
		}

		var left, right syntax.Syntax

		// 初始化 cacheOperToken 为 syntax 与 参数 syntaxStatment 计算优先级合并
		_syntax := operSyntaxParse(cacheOperToken.Token, stream, input)
		switch _syntax.Kind() {
		case 1:
			// 没有左值 参数 / 常量
			left = syntaxArgs[0]
			_syntax.ChangeLeft(left)
			cacheOperTokens = cacheOperTokens[:len(cacheOperTokens)-1]
			syntaxStatementStack = append(syntaxStatementStack[:len(syntaxStatementStack)-cacheOperToken.Kind], _syntax)
		case 2:
			// 左右值 可能是逻辑/比较/数学运算符
			// 需要考虑其优先级(特别是数学运算符)

			left = syntaxArgs[0]
			right = syntaxArgs[1]

			if left.Kind() == 2 {
				//
				if left.Priority() > _syntax.Priority()+5 {
					// 优先级高
					_syntax.ChangeLeft(left.Right())
					_syntax.ChangeRight(right)
					left.ChangeRight(_syntax)
					_syntax = left
					cacheOperTokens = cacheOperTokens[:len(cacheOperTokens)-1]
					syntaxStatementStack = append(syntaxStatementStack[:len(syntaxStatementStack)-cacheOperToken.Kind], _syntax)
				} else {
					// 优先级低
					_syntax.ChangeLeft(left)
					_syntax.ChangeRight(right)
					cacheOperTokens = cacheOperTokens[:len(cacheOperTokens)-1]
					syntaxStatementStack = append(syntaxStatementStack[:len(syntaxStatementStack)-cacheOperToken.Kind], _syntax)
				}
			} else {
				_syntax.ChangeLeft(left)
				_syntax.ChangeRight(right)
				cacheOperTokens = cacheOperTokens[:len(cacheOperTokens)-1]
				syntaxStatementStack = append(syntaxStatementStack[:len(syntaxStatementStack)-cacheOperToken.Kind], _syntax)
			}

		}

		// 根据优先级组合成新的 syntax statment
		// 合并 syntaxStatement 栈
		// syntaxStatementStack = append(syntaxStatementStack[:len(syntaxStatementStack)-cacheOperToken.Kind], _syntax)
	}
	return cacheOperTokens, syntaxStatementStack
}

// 内置函数语法解析器
func builtinFunctionParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) syntax.Syntax {

	curlyOpen := stream.GoNext().CurrentToken()
	// 必须是 (
	if !expectType(curlyOpen, []tokenizer.TokenKey{TCurlyOpen}) {
		parsePanic(fmt.Sprintf("syntax error, %s must with \"(\"", token.ValueString()), token, stream, input)
	}

	vToken := stream.GoNext().CurrentToken()
	val := vToken.ValueString()
	// 必须是 StringConstant
	if !expectType(vToken, []tokenizer.TokenKey{tokenizer.TokenString}) {
		parsePanic(fmt.Sprintf("grammatical error, you need input string. example: %s(\"something\")\n", token.ValueString()), token, stream, input)
	}

	curlyClose := stream.GoNext().CurrentToken() // 必须是 )
	if !expectType(curlyClose, []tokenizer.TokenKey{TCurlyClose}) {
		parsePanic(fmt.Sprintf("%s(%s 没有闭合括号\n", token.ValueString(), vToken.ValueString()), token, stream, input)
	}

	// 后推断检查
	// nextToken := stream.GoNext().CurrentToken()
	nextToken := stream.NextToken()
	if nextToken.IsValid() && !expectStringValue(nextToken, []string{"and", "or", ")"}) {
		parsePanic(fmt.Sprintf("%s(%s)\" %s only supports \"and\" and \"or\" constructions.\n", token.ValueString(), vToken.ValueString(), nextToken.ValueString()), token, stream, input)
	}

	tokenString := token.ValueString()
	switch tokenString {
	case "Role":
		return value.NewRoleSyntax(val)
	case "Permission":
		return value.NewPermissionSyntax(val)
	case "Group":
		return value.NewGroupSyntax(val)
	case "Roles", "Permissions", "Groups":
		parsePanic("暂不支持 Roles,Permissions,Groups", token, stream, input)
	}
	parsePanic("无效的内置函数", token, stream, input)
	return nil
}

// 变量解析器
func paramSyntaxParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) syntax.Syntax {
	strToken := stream.GoNext().CurrentToken()
	if expectType(strToken, []tokenizer.TokenKey{tokenizer.TokenKeyword}) {
		return value.NewParamSyntax(strToken.ValueString())
	}
	parsePanic("错误变量表达式", token, stream, input)
	return nil
}

// 字符串常量解析器
func constantSyntaxParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) syntax.Syntax {
	switch token.Key() {
	case tokenizer.TokenString:
		return value.NewConstantSyntax(token.ValueString())
	case tokenizer.TokenInteger:
		return value.NewConstantSyntax(token.ValueInt64())
	case tokenizer.TokenFloat:
		return value.NewConstantSyntax(token.ValueFloat64())
	}
	parsePanic("错误常量表达式,目前仅支持字符串/数字常量", token, stream, input)
	return nil
}

// 值语句解析
func valueSyntaxParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) syntax.Syntax {
	if expectType(token, []tokenizer.TokenKey{tokenizer.TokenString, tokenizer.TokenInteger, tokenizer.TokenFloat}) {
		// Constant[String|Number] / Param
		return constantSyntaxParse(token, stream, input)
	} else if expectType(token, []tokenizer.TokenKey{TPlaceholder}) {
		return paramSyntaxParse(token, stream, input)
	} else if expectType(token, []tokenizer.TokenKey{TRole, TPermission, TGroup}) {
		// Role/Permission/Group
		return builtinFunctionParse(token, stream, input)
	}
	// * Roles/Permissions/Groups

	// *Array : in(...)

	parsePanic("unknow value syntax", token, stream, input)
	return nil
}

// 操作语句解析
func operSyntaxParse(token *tokenizer.Token, stream *tokenizer.Stream, input string) syntax.Syntax {
	switch token.ValueString() {
	case "+":
		return oper.NewAddSyntax(nil, nil)
	case "-":
		return oper.NewSubSyntax(nil, nil)
	case "*":
		return oper.NewMulSyntax(nil, nil)
	case "/":
		return oper.NewDivSyntax(nil, nil)
	case "%":
		return oper.NewModSyntax(nil, nil)
	case "==":
		return oper.NewEqSyntax(nil, nil)
	case "!=":
		return oper.NewNotEqSyntax(nil, nil)
	case ">":
		return oper.NewGtSyntax(nil, nil)
	case ">=":
		return oper.NewGteSyntax(nil, nil)
	case "<":
		return oper.NewLtSyntax(nil, nil)
	case "<=":
		return oper.NewLteSyntax(nil, nil)
	case "and":
		return oper.NewAndSyntax(nil, nil)
	case "or":
		return oper.NewOrSyntax(nil, nil)
	case "!":
		return oper.NewNegateSyntax(nil)
	}

	parsePanic("unknow oper syntax", token, stream, input)
	return nil
}

// expectValueToken
// 检查当前token值 是否属于 "值Token" (ValueToken)
func expectValueToken(token *tokenizer.Token) bool {
	switch token.Key() {
	case TRole, TPermission, TGroup, tokenizer.TokenString, TPlaceholder, tokenizer.TokenFloat, tokenizer.TokenInteger:
		return true
	}

	return false
}

// expectOperToken
// 检查当前token值 是否属于 "操作Token" (OperToken)
// func expectOperToken(token *tokenizer.Token) bool {
// 	switch token.ValueString() {
// 	case "+", "-", "*", "/", "%", "and", "or", "!", "==", "!=", ">=", ">", "<=":
// 		return true
// 	}

// 	return false
// }

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

func parsePanic(msg string, token *tokenizer.Token, stream *tokenizer.Stream, input string) {
	limitLen := len(input)
	if limitLen > token.Offset()+25 {
		limitLen = token.Offset() + 25
	}
	before := input[:token.Offset()]
	after := input[token.Offset():limitLen]
	errorContext := before + "﹏" + after + "..."
	panic(fmt.Sprintf("[%d:%d] \"%s\": %s, %s", token.Line(), token.Offset(), token.ValueString(), msg, errorContext))
}
