package parse

import (
	"fmt"
	"sort"
	"testing"
)

func BenchmarkMapping(b *testing.B) {
	patterns := []string{
		"/orders/*/:orderId?categoryId=:category",
		"/order/list?category=${category}",
		"/order/details",
		"/order/history",
		"/order/*",
		"/users/:user/order/list?category=${category}",
		"/users/:user/profile",
		"/buckets/*/files/*/date/:year/:month/:day?fileType=:fileType",
		"/files/images/:category",
	}
	router := NewRouter(patterns)
	b.Logf("b.N = %d", b.N)
	for range b.N {
		router.MatchPath("/users/123/order/list?category=book")
		// pattern, params, err := router.Find("/users/123/order/list?category=book")
		// if err != nil {
		// 	b.Logf("err : %v", err)
		// }
		// b.Logf("pattern: %s, params: %v", pattern, params)
	}
}

func TestTree(t *testing.T) {
	// 1. 批量创建路由树
	patterns := []string{
		"/orders/*/:orderId?categoryId=:category",
		"/order/list?category=${category}",
		"/order/details",
		"/order/history",
		"/order/*",
		"/users/:user/order/list?category=${category}",
		"/users/:user/profile",
		"/users/:userx/friends",
		"/buckets/*/files/*/date/:year/:month/:day?fileType=:fileType",
		"/files/images/:category",
	}
	router := NewRouter(patterns)

	// 2. 打印路由树结构
	router.PrintTree()
	fmt.Println("\n路由匹配测试:")

	// 测试路由匹配
	testCases := []struct {
		path     string
		expected string
	}{
		{"/users/123/order/list?category=book", "/users/:user/order/list?category=${category}"},
		{"/users/456/profile", "/users/:user/profile"},
		{"/files/bigFile/date/2020/01/01", "/files/*/date/:year/:month/:day"},
		{"/buckets/huanan/files/bigFile/date/2020/01/01", "/buckets/*/files/*/date/:year/:month/:day"},
		{"/files/images/nature", "/files/images/:category"},
		{"/orders/123/456?categoryId=books", "/orders/*/:orderId?categoryId=:category"},
		{"/order/list?category=electronics", "/order/list?category=${category}"},
		{"/order/details", "/order/details"},
		{"/order/history", "/order/history"},
		{"/order/any/path", "/order/*"},
		{"/order/any", "/order/*"},
		{"/not/found", ""},
	}

	for _, tc := range testCases {
		pattern, params, err := router.Match(tc.path)
		if tc.expected == "" {
			if err == nil {
				fmt.Printf("路径: %-40s 预期: 不匹配, 实际: 匹配 %s ✗\n", tc.path, pattern)
			} else {
				fmt.Printf("路径: %-40s 预期: 不匹配, 实际: 不匹配 ✓\n", tc.path)
			}
			continue
		}

		if err != nil {
			fmt.Printf("路径: %-40s 错误: %v ✗\n", tc.path, err)
			continue
		}

		fmt.Printf("路径: %-40s 匹配: %-60s", tc.path, pattern)
		if pattern == tc.expected {
			fmt.Print("✓")
		} else {
			fmt.Print("✗")
		}
		if len(params) > 0 {
			// 对参数键进行排序，以便输出一致
			keys := make([]string, 0, len(params))
			for k := range params {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			// 构建有序参数输出
			paramStr := "参数: {"
			for i, k := range keys {
				if i > 0 {
					paramStr += ", "
				}
				paramStr += fmt.Sprintf("%s:%s", k, params[k])
			}
			paramStr += "}"
			fmt.Print(" ", paramStr)
		}
		fmt.Println()
	}
}
