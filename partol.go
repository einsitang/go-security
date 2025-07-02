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

type Partol interface {
	// 添加检查端点
	//
	// endpoint: 端点； express: 检查表达式
	AddEndpoint(endpoint string, express string) error

	// 检查 用户(principal) 在端点(endpoint) 内是否符合通行规则
	//
	// 如果该端点命中规则表达式，则返回 true,nil , 否则返回 false,nil
	//
	// 如果出现error,则表示该端点没有建立规则，默认放行
	Check(endpoint string, principal SecurityPrincipal) (pass bool, err error)

	// 清空所有检查端点
	CleanEndpoints()
}

type partol struct {
	router *parse.Router
	guards map[string]Guard
}

func (p *partol) AddEndpoint(endpoint string, express string) error {

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

func (p *partol) Check(endpoint string, principal SecurityPrincipal) (bool, error) {
	pattern, params, err := p.router.Match(endpoint)
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
		Params:    params,
		Principal: principal,
	}), nil
}

func (p *partol) CleanEndpoints() {
	p.router = parse.NewRouter([]string{})
	p.guards = map[string]Guard{}
}

func NewPartol(options ...PortalOption) (Partol, error) {

	p := &partol{
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

type PortalOption func(p *partol) error

func WithConfig(configPath string) PortalOption {
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

	return func(p *partol) error {
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
