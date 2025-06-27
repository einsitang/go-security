package parse

import (
	"fmt"
	"strings"
)

// Match 严格匹配路径和查询参数
func Match(fullPath, pattern string) (bool, map[string]string, error) {
	// 分割路径和查询参数
	pathPart, queryPart := splitPathAndQuery(fullPath)
	patternPath, patternQuery := splitPathAndQuery(pattern)

	// 匹配路径部分
	pathMatch, pathParams, err := matchPath(pathPart, patternPath)
	if !pathMatch || err != nil {
		return false, nil, err
	}

	// 解析实际查询参数
	actualQueryParams := parseQueryString(queryPart)

	// 解析模式查询参数
	patternQueryParams := parseQueryParams(patternQuery)

	// 检查查询参数匹配
	for param := range patternQueryParams {
		if _, exists := actualQueryParams[param]; !exists {
			return false, nil, fmt.Errorf("missing required query parameter: %s", param)
		}
	}

	// 合并参数
	params := make(map[string]string)
	for k, v := range pathParams {
		params[k] = v
	}
	for k, v := range actualQueryParams {
		params[k] = v
	}

	return true, params, nil
}

// MatchPath 只匹配路径部分，忽略查询参数
func MatchPath(fullPath, pattern string) (bool, map[string]string, error) {
	// 分割路径和查询参数
	pathPart, queryPart := splitPathAndQuery(fullPath)
	patternPath, patternQuery := splitPathAndQuery(pattern)

	// 匹配路径部分
	match, pathParams, err := matchPath(pathPart, patternPath)
	if !match || err != nil {
		return false, nil, err
	}

	// 解析实际查询参数
	actualQueryParams := parseQueryString(queryPart)

	// 解析模式查询参数
	patternQueryParams := parseQueryParams(patternQuery)

	// 合并参数
	params := make(map[string]string)
	for k, v := range pathParams {
		params[k] = v
	}
	for k, _ := range patternQueryParams {
		params[k] = actualQueryParams[k]
	}
	// 返回路径参数
	return true, params, nil
}

// matchPath 匹配路径部分
func matchPath(path, pattern string) (bool, map[string]string, error) {
	// 分割路径段
	pathSegments := splitPath(path)
	patternSegments := splitPath(pattern)

	params := make(map[string]string)
	wildcardCount := 0
	pathIndex := 0
	patternIndex := 0

	for patternIndex < len(patternSegments) {
		// 如果路径已结束但模式还有剩余
		if pathIndex >= len(pathSegments) {
			return false, nil, nil
		}

		patternSeg := patternSegments[patternIndex]
		pathSeg := pathSegments[pathIndex]

		switch {
		case patternSeg == "*": // 通配符
			// 收集剩余所有路径段
			remaining := strings.Join(pathSegments[pathIndex:], "/")
			// fmt.Printf("匹配通配符: %s -> %s\n", patternSeg, remaining)
			params[fmt.Sprintf("$%d", wildcardCount)] = remaining
			wildcardCount++
			pathIndex = len(pathSegments) // 跳过剩余路径
			patternIndex++

		case strings.HasPrefix(patternSeg, ":"): // 参数节点
			paramName := patternSeg[1:]
			params[paramName] = pathSeg
			pathIndex++
			patternIndex++

		case patternSeg == pathSeg: // 静态匹配
			pathIndex++
			patternIndex++

		default: // 不匹配
			return false, nil, nil
		}
	}

	// 检查是否所有路径段都已匹配
	if pathIndex < len(pathSegments) {
		return false, nil, nil
	}

	return true, params, nil
}

// parseQueryString 解析查询字符串
func parseQueryString(query string) map[string]string {
	params := make(map[string]string)
	if query == "" {
		return params
	}

	pairs := strings.Split(query, "&")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 0 {
			continue
		}

		key := kv[0]
		if key == "" {
			continue
		}

		value := ""
		if len(kv) > 1 {
			value = kv[1]
		}

		if _, exists := params[key]; !exists {
			params[key] = value
		}
	}
	return params
}
