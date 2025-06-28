package parse

import (
	"fmt"
	"log"
	"sort"
	"strings"
)

// Router 路由树结构
type Router struct {
	// root *node // 根节点
	roots map[string]*node // 根节点
}

// node 路由树节点
type node struct {
	method         string           // 方法
	segment        string           // 当前路径段
	nodeType       int              // 节点类型（0=静态, 1=参数, 2=通配符）
	staticChildren map[string]*node // 静态子节点映射表
	paramChild     *node            // 参数子节点
	wildcard       *node            // 通配符子节点
	pattern        string           // 完整路由模式（仅叶节点）
	queryPattern   string           // 查询参数模式
	paramNames     []string         // 参数名称列表（路径参数）
	wildcardCnt    int              // 通配符数量
	queryParams    map[string]bool  // 查询参数中的变量
}

// 节点类型常量
const (
	nodeTypeStatic = iota
	nodeTypeParam
	nodeTypeWildcard
)

// NewRouter 创建新的路由树
func NewRouter(patterns []string) *Router {
	router := &Router{
		roots: make(map[string]*node),
		// root: &node{
		// 	segment:        "/",
		// 	nodeType:       nodeTypeStatic,
		// 	staticChildren: make(map[string]*node),
		// },
	}
	if len(patterns) > 0 {
		router.Add(patterns...)
	}
	return router
}

// Add 添加一个或多个路由规则
func (r *Router) Add(endpoints ...string) {
	for _, endpoint := range endpoints {

		methods, pattern := splitMethodAndPattern(endpoint)
		// 分割路径和查询参数
		pathPart, queryPart := splitPathAndQuery(pattern)
		pathSegments := splitPath(pathPart)

		// 计算通配符数量
		wildcardCnt := countWildcards(pathSegments)

		// 解析查询参数中的变量
		queryParams := parseQueryParams(queryPart)

		for _, _method := range methods {
			method := strings.ToUpper(_method)

			root, ok := r.roots[method]
			if !ok {
				root = &node{
					method:         method,
					segment:        "/",
					nodeType:       nodeTypeStatic,
					staticChildren: make(map[string]*node),
				}
				r.roots[method] = root
			}
			// 添加到路由树
			root.addRoute(method, pathSegments, pattern, queryPart, queryParams, wildcardCnt)
		}
	}
}

func (r *Router) match(method string, fullPath string) (pattern string, params map[string]any, err error) {
	// 分割路径和查询参数
	pathPart, queryPart := splitPathAndQuery(fullPath)
	pathSegments := splitPath(pathPart)

	// 查找路径匹配
	root, ok := r.roots[method]
	if !ok {
		return "", nil, fmt.Errorf("no matching route found for: %s", fullPath)
	}

	pathParams, leafNode, wildcardValues := root.findRoute(pathSegments, nil, nil)
	if leafNode == nil {
		return "", nil, fmt.Errorf("no matching route found for: %s", fullPath)
	}

	// 解析实际URL的查询参数
	actualQueryParams := parseActualQueryParams(queryPart)

	// 创建参数映射
	params = make(map[string]any)

	// 添加通配符参数（$0, $1, ...）
	for i, val := range wildcardValues {
		params[fmt.Sprintf("$%d", i)] = val
	}

	// 添加路径参数
	for k, v := range pathParams {
		params[k] = v
	}

	// 添加查询参数
	for k, v := range actualQueryParams {
		params[k] = v
	}

	// 检查查询参数匹配
	if !matchQueryParams(leafNode.queryParams, actualQueryParams) {
		return "", nil, fmt.Errorf("query parameters do not match for route: %s", leafNode.pattern)
	}

	// 返回完整模式
	return leadfNodePattern(leafNode), params, nil
}

// Match 严格匹配路由（包括路径和查询参数）
func (r *Router) Match(endpoint string) (pattern string, params map[string]any, err error) {
	methods, fullPath := splitMethodAndPattern(endpoint)
	method := strings.ToUpper(methods[0])

	if method == "" {
		return r.match(method, fullPath)
	}
	pattern, params, err = r.match(method, fullPath)
	if err != nil {
		// 没找到，从 空 root 中再次尝试匹配
		return r.match("", fullPath)
	}

	return pattern, params, err
}

func (r *Router) matchPath(method string, fullPath string) (pattern string, params map[string]string, err error) {

	root, ok := r.roots[method]
	if !ok {
		return "", nil, fmt.Errorf("no matching route found for: %s", fullPath)
	}

	// 分割路径和查询参数
	pathPart, queryPart := splitPathAndQuery(fullPath)
	pathSegments := splitPath(pathPart)

	// 查找路径匹配
	pathParams, leafNode, wildcardValues := root.findRoute(pathSegments, nil, nil)
	if leafNode == nil {
		return "", nil, fmt.Errorf("no matching route found for: %s", fullPath)
	}

	// 解析实际URL的查询参数
	actualQueryParams := parseActualQueryParams(queryPart)

	// 创建参数映射
	params = make(map[string]string)

	// 添加通配符参数（$0, $1, ...）
	for i, val := range wildcardValues {
		params[fmt.Sprintf("$%d", i)] = val
	}

	// 添加路径参数
	for k, v := range pathParams {
		params[k] = v
	}

	// 添加查询参数（提取所有查询参数值）
	for k, v := range actualQueryParams {
		params[k] = v
	}

	// 返回完整模式
	return leadfNodePattern(leafNode), params, nil
}

// MatchPath 只匹配路径部分，忽略查询参数匹配
func (r *Router) MatchPath(endpoint string) (pattern string, params map[string]string, err error) {

	methods, fullPath := splitMethodAndPattern(endpoint)
	method := strings.ToUpper(methods[0])

	if method == "" {
		return r.matchPath(method, fullPath)
	}
	pattern, params, err = r.matchPath(method, fullPath)
	if err != nil {
		// 没找到，从 空 root 中再次尝试匹配
		return r.matchPath("", fullPath)
	}

	return pattern, params, err
}

func leadfNodePattern(leafNode *node) string {
	return strings.Trim(fmt.Sprintf("%s %s", leafNode.method, leafNode.pattern), " ")
}

func splitMethodAndPattern(endpoint string) ([]string, string) {
	var pattern string
	var methods []string
	// 分割方法
	matchStr, pattern, ok := strings.Cut(endpoint, " ")
	if !ok {
		methods = []string{""}
		pattern = endpoint
	} else {
		methods = strings.Split(strings.Trim(matchStr, "/"), "/")
	}
	pattern = strings.Trim(pattern, " ")
	return methods, pattern
}

// 检查查询参数是否匹配
func matchQueryParams(ruleParams map[string]bool, actualParams map[string]string) bool {
	// 规则中定义了查询参数变量，则实际URL必须包含这些参数
	for param := range ruleParams {
		found := false
		for actualKey := range actualParams {
			// 参数名匹配（支持 :param 和 ${param} 形式）
			if actualKey == param || strings.TrimPrefix(actualKey, "$") == param {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// splitPathAndQuery 分割路径和查询参数
func splitPathAndQuery(fullPath string) (path, query string) {
	if idx := strings.Index(fullPath, "?"); idx != -1 {
		return fullPath[:idx], fullPath[idx+1:]
	}
	return fullPath, ""
}

// splitPath 将路径分割为段
func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "/")
}

// parseQueryParams 解析查询参数中的变量
func parseQueryParams(query string) map[string]bool {
	params := make(map[string]bool)
	if query == "" {
		return params
	}

	values, _ := urlParseQuery(query)
	for _, vals := range values {
		for _, val := range vals {
			// 提取变量名（支持 :var 和 ${var} 形式）
			if strings.HasPrefix(val, ":") {
				paramName := val[1:]
				params[paramName] = true
			} else if strings.HasPrefix(val, "${") && strings.HasSuffix(val, "}") {
				paramName := val[2 : len(val)-1]
				params[paramName] = true
			}
		}
	}
	return params
}

// parseActualQueryParams 解析实际URL的查询参数
func parseActualQueryParams(query string) map[string]string {
	params := make(map[string]string)
	if query == "" {
		return params
	}

	values, _ := urlParseQuery(query)
	for key, vals := range values {
		if len(vals) > 0 {
			params[key] = vals[0]
		}
	}
	return params
}

func urlParseQuery(query string) (map[string][]string, error) {
	result := make(map[string][]string)

	// 如果查询字符串为空，直接返回空结果
	if query == "" {
		return result, nil
	}

	// 按 '&' 分割查询字符串
	pairs := strings.Split(query, "&")

	for _, pair := range pairs {
		if pair == "" {
			continue
		}

		// 按 '=' 分割键值对
		kv := strings.SplitN(pair, "=", 2)
		key := kv[0]
		var value string

		if len(kv) == 1 {
			value = "" // 无值的情况
		} else {
			var err error
			// 对值进行 URL 解码
			value, err = queryUnescape(kv[1])
			if err != nil {
				return nil, fmt.Errorf("failed to unescape value %q: %w", kv[1], err)
			}
		}

		// 将值追加到对应的键中
		result[key] = append(result[key], value)
	}

	return result, nil
}

// countWildcards 计算路径中的通配符数量
func countWildcards(segments []string) int {
	cnt := 0
	for _, seg := range segments {
		if seg == "*" {
			cnt++
		}
	}
	return cnt
}

// addRoute 添加路由到节点
func (n *node) addRoute(method string, segments []string, pattern, queryPart string, queryParams map[string]bool, wildcardCnt int) {
	if len(segments) == 0 {
		// 叶节点：保存完整信息
		n.method = method
		n.pattern = pattern
		n.queryPattern = queryPart
		n.queryParams = queryParams
		n.wildcardCnt = wildcardCnt
		return
	}

	currentSeg := segments[0]
	remaining := segments[1:]

	switch {
	case currentSeg == "*": // 通配符节点
		if n.wildcard == nil {
			n.wildcard = &node{
				method:         method,
				segment:        "*",
				nodeType:       nodeTypeWildcard,
				staticChildren: make(map[string]*node),
			}
		}
		n.wildcard.addRoute(method, remaining, pattern, queryPart, queryParams, wildcardCnt)

	case strings.HasPrefix(currentSeg, ":"): // 参数节点
		paramName := currentSeg[1:]
		if n.paramChild == nil {
			n.paramChild = &node{
				method:         method,
				segment:        currentSeg,
				nodeType:       nodeTypeParam,
				staticChildren: make(map[string]*node),
			}

			// 记录参数名
			n.paramNames = append(n.paramNames, paramName)
		} else if n.paramChild.segment != currentSeg {
			log.Printf("Warning: Endpoint ( %s ) node \"%s\" conflicts with existing node \"%s\", which may cause parameter errors\n", pattern, currentSeg, n.paramChild.segment)
			log.Printf("fix endpoint use \"%s\" replace \"%s\" \n", strings.ReplaceAll(pattern, currentSeg, n.paramChild.segment), pattern)
		}
		n.paramChild.addRoute(method, remaining, pattern, queryPart, queryParams, wildcardCnt)

	default: // 静态节点
		// 初始化staticChildren映射（如果尚未初始化）
		if n.staticChildren == nil {
			n.staticChildren = make(map[string]*node)
		}

		// 查找或创建静态子节点
		child, exists := n.staticChildren[currentSeg]
		if !exists {
			child = &node{
				method:         method,
				segment:        currentSeg,
				nodeType:       nodeTypeStatic,
				staticChildren: make(map[string]*node),
			}
			n.staticChildren[currentSeg] = child
		}
		child.addRoute(method, remaining, pattern, queryPart, queryParams, wildcardCnt)
	}
}

// findRoute 在节点中查找匹配的路由
func (n *node) findRoute(segments []string, params map[string]string, wildcardValues []string) (map[string]string, *node, []string) {
	if len(segments) == 0 {
		if n.pattern != "" {
			return params, n, wildcardValues
		}
		return nil, nil, nil
	}

	currentSeg := segments[0]
	remaining := segments[1:]

	// 1. 尝试匹配静态节点
	if n.staticChildren != nil {
		if child, exists := n.staticChildren[currentSeg]; exists {
			return child.findRoute(remaining, params, wildcardValues)
		}
	}

	// 2. 尝试匹配参数节点
	if n.paramChild != nil {
		if params == nil {
			params = make(map[string]string)
		}
		// 使用第一个参数名
		if len(n.paramNames) > 0 {
			params[n.paramNames[0]] = currentSeg
		}
		return n.paramChild.findRoute(remaining, params, wildcardValues)
	}

	// 3. 尝试匹配通配符节点
	if n.wildcard != nil {
		if wildcardValues == nil {
			wildcardValues = make([]string, 0, n.wildcardCnt)
		}
		// 通配符节点匹配剩余所有路径
		fullWildcard := strings.Join(segments, "/")
		wildcardValues = append(wildcardValues, fullWildcard)
		return n.wildcard.findRoute(nil, params, wildcardValues)
	}

	// 没有匹配
	return nil, nil, nil
}

// PrintTree 打印路由树结构（调试用）
func (r *Router) PrintTree() {
	fmt.Println("路由树结构:")
	for _, root := range r.roots {
		printNode(root, "", true)
		fmt.Println("--- --- --- --- --- ---")
	}
}

// printNode 递归打印节点及其子树
func printNode(n *node, indent string, isLast bool) {
	// 节点类型描述
	typeDesc := ""
	switch n.nodeType {
	case nodeTypeStatic:
		typeDesc = "静态"
	case nodeTypeParam:
		typeDesc = "参数"
	case nodeTypeWildcard:
		typeDesc = "通配符"
	}

	// 节点描述
	desc := fmt.Sprintf("%s: %s [ %s ]", typeDesc, n.segment, n.method)
	if n.pattern != "" {
		desc += fmt.Sprintf(" -> [%s]", n.pattern)
	}
	if n.wildcardCnt > 0 {
		desc += fmt.Sprintf(" (通配符数: %d)", n.wildcardCnt)
	}
	if n.queryPattern != "" {
		desc += fmt.Sprintf(" ? %s", n.queryPattern)
	}
	if len(n.queryParams) > 0 {
		params := make([]string, 0, len(n.queryParams))
		for param := range n.queryParams {
			params = append(params, param)
		}
		sort.Strings(params)
		desc += fmt.Sprintf(" (查询参数: %v)", params)
	}
	if len(n.paramNames) > 0 {
		desc += fmt.Sprintf(" (参数: %v)", n.paramNames)
	}

	// 打印当前节点
	marker := "├── "
	if isLast {
		marker = "└── "
	}
	fmt.Printf("%s%s%s\n", indent, marker, desc)

	// 计算下一级缩进
	newIndent := indent
	if isLast {
		newIndent += "    "
	} else {
		newIndent += "│   "
	}

	// 收集所有子节点
	children := []*node{}

	// 添加静态子节点
	if n.staticChildren != nil {
		for _, child := range n.staticChildren {
			children = append(children, child)
		}
	}

	// 添加参数子节点
	if n.paramChild != nil {
		children = append(children, n.paramChild)
	}

	// 添加通配符子节点
	if n.wildcard != nil {
		children = append(children, n.wildcard)
	}

	// 按节点类型排序以保持一致性
	sort.Slice(children, func(i, j int) bool {
		return children[i].segment < children[j].segment
	})

	// 打印子节点
	for i, child := range children {
		isLastChild := i == len(children)-1
		printNode(child, newIndent, isLastChild)
	}
}
