package security

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/einsitang/go-security/internal/expr/ctx"
	"github.com/einsitang/go-security/internal/parse"
)

type SecurityPrincipal ctx.Principal
type SecurityContext ctx.Context

// 哨兵
//
// 看守全局路由的哨兵模式
type Sentinel interface {

	/*
		添加检查点

		pattern: 端点表达式； express: 检查表达式
	*/
	AddEndpoint(pattern string, express string) error

	/*
		检查 用户(principal) 在端点(endpoint) 内是否符合通行规则

		customParams 为自定义参数(可为nil),用于根据实际情况传递给表达式进行逻辑计算

		如果该端点命中规则表达式，则返回 true,nil , 否则返回 false,nil

		如果 error != nil

		- 没有建立规则

		- 规则执行错误，大概率是因为类型转换问题，因为规则在AddEndpoint阶段会编译AST,如果出错会在这个环节报 error
	*/
	check(endpoint string, principal SecurityPrincipal, customParams map[string]string, strict bool) (pass bool, err error)

	/*
		检查 用户(principal) 在端点(endpoint) 内是否符合通行规则

		customParams 为自定义参数(可为nil),用于根据实际情况传递给表达式进行逻辑计算

		端点匹配时不检查QueryParams参数

		该方法实际执行 check(endpoint,principal,false)

		碰到 err != nil 应该忽略 pass 值
	*/
	Check(endpoint string, principal SecurityPrincipal, customParams map[string]string) (pass bool, err error)

	/*
		检查 用户(principal) 在端点(endpoint) 内是否符合通行规则

		customParams 为自定义参数(可为nil),用于根据实际情况传递给表达式进行逻辑计算

		端点匹配时严格检查QueryParams参数

		该方法实际执行 check(endpoint,principal,customParams,true)

		碰到 err != nil 应该忽略 pass 值
	*/
	StrictCheck(endpoint string, principal SecurityPrincipal, customParams map[string]string) (pass bool, err error)

	// 清空所有检查端点
	CleanEndpoints()
}

type sentinel struct {
	router *parse.Router
	guards map[string]Guard
}

func (p *sentinel) AddEndpoint(endpoint string, express string) error {

	p.router.Add(endpoint)

	var methods []string
	methodStr, pattern, ok := strings.Cut(endpoint, " ")
	if !ok {
		methods = []string{""}
		pattern = endpoint
	} else {
		methods = strings.Split(strings.Trim(methodStr, "/"), "/")
	}

	for _, method := range methods {
		key := method + " " + pattern
		key = strings.Trim(key, " ")
		if _, ok := p.guards[key]; ok {
			return fmt.Errorf("endpoint %s already exists", key)
		}

		guard, err := NewGuard(express)
		if err != nil {
			fmt.Println("here")
			return err
		}

		p.guards[key] = guard
	}
	return nil
}

func (p *sentinel) Check(endpoint string, principal SecurityPrincipal, customParams map[string]string) (bool, error) {
	return p.check(endpoint, principal, customParams, false)
}

func (p *sentinel) StrictCheck(endpoint string, principal SecurityPrincipal, customParams map[string]string) (bool, error) {
	return p.check(endpoint, principal, customParams, true)
}

func (p *sentinel) check(endpoint string, principal SecurityPrincipal, customParams map[string]string, strict bool) (bool, error) {
	var matchFn func(endpoint string) (pattern string, params map[string]any, err error)
	if strict {
		matchFn = p.router.Match
	} else {
		matchFn = p.router.MatchPath
	}
	pattern, params, err := matchFn(endpoint)
	if err != nil {
		return false, err
	}

	var key string
	method, _, ok := strings.Cut(endpoint, " ")
	if !ok {
		key = pattern
	} else {
		key = method + " " + pattern
	}

	guard, ok := p.guards[key]
	if !ok && key != pattern {
		// 尝试匹配空方法
		guard, ok = p.guards[pattern]
		if !ok {
			// 没有匹配上
			return true, nil
		}
	}

	return guard.Check(&SecurityContext{
		Params:       params,
		Principal:    principal,
		CustomParams: customParams,
	})
}

func (p *sentinel) CleanEndpoints() {
	p.router = parse.NewRouter([]string{})
	p.guards = map[string]Guard{}
}

func NewSentinel(options ...SentinelOption) (Sentinel, error) {

	p := &sentinel{
		router: parse.NewRouter([]string{}),
		guards: map[string]Guard{},
	}

	for _, option := range options {
		if err := option(p); err != nil {
			return nil, err
		}
	}

	return p, nil
}

type SentinelOption func(p *sentinel) error

func WithConfig(configPath string) SentinelOption {
	file, err := os.Open(configPath)
	if err != nil {
		panic(err)
	}
	defer func() {
		file.Close()
	}()
	content, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}

	text := string(content)

	return func(p *sentinel) error {
		lines := strings.Split(text, "\n")
		for lineIndex, line := range lines {
			if strings.HasPrefix(line, "#") {
				// 注释行 跳过
				continue
			}
			endpoint, express, ok := strings.Cut(line, ",")
			if !ok {
				return fmt.Errorf("\"%s\" -> invalid line[#%d]: \"%s\"", configPath, lineIndex, line)
			}
			err := p.AddEndpoint(endpoint, express)
			if err != nil {
				return err
			}
		}
		return nil
	}
}
