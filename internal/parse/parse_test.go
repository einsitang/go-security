package parse

import (
	"fmt"
	"sort"
	"testing"
)

func BenchmarkMatch(b *testing.B) {
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
	b.Logf("b.N = %d", b.N)
	for range b.N {
		for _, pattern := range patterns {
			MatchPath("/users/123/order/list?category=book", pattern)
		}
		// pattern, params, err := router.Find("/users/123/order/list?category=book")
		// if err != nil {
		// 	b.Logf("err : %v", err)
		// }
		// b.Logf("pattern: %s, params: %v", pattern, params)
	}
}

func TestParse(t *testing.T) {

	// 定义路由模式
	patterns := []string{
		"/orders/*/:orderId?categoryId=:category",
		"/order/list?category=${category}",
		"/order/*",
		"/users/:user/order/list?category=${category}",
		"/files/*/date/:year/:month/:day",
		"/a/:name",
	}

	// 测试路径
	testPaths := []string{
		"/order/list?category=book",
		"/order/any/path",
		"/users/123/order/list?category=electronics",
		"/files/reports/date/2023/10/15",
		"/orders/123/456?categoryId=books",
		"/not/matching/path",
		"/a/hello?next=world",
	}

	fmt.Println("路由匹配测试 (Match - 严格匹配):")
	for _, path := range testPaths {
		var matched bool
		var params map[string]string
		var matchPattern string

		for _, pattern := range patterns {
			if match, p, _ := Match(path, pattern); match {
				matched = true
				params = p
				matchPattern = pattern
				break
			}
		}

		if matched {
			fmt.Printf("路径: %-40s 匹配: %-50s", path, matchPattern)
			fmt.Print("✓")
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
		} else {
			fmt.Printf("路径: %-40s 未匹配任何模式\n", path)
		}
	}

	fmt.Println("\n路由匹配测试 (MatchPath - 路径匹配):")
	for _, path := range testPaths {
		var matched bool
		var params map[string]string
		var matchPattern string

		for _, pattern := range patterns {
			if match, p, _ := MatchPath(path, pattern); match {
				matched = true
				params = p
				matchPattern = pattern
				break
			}
		}

		if matched {
			fmt.Printf("路径: %-40s 匹配: %-50s", path, matchPattern)
			fmt.Print("✓")
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
		} else {
			fmt.Printf("路径: %-40s 未匹配任何模式\n", path)
		}
	}

}
