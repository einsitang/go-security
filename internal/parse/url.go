package parse

import "fmt"

func queryUnescape(s string) (string, error) {
	// 创建一个字节切片来存储结果
	result := make([]byte, 0, len(s))

	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			// 检查是否还有足够的字符来解析百分号编码
			if i+2 >= len(s) {
				return "", fmt.Errorf("invalid URL escape: %s", s[i:])
			}

			// 解析两位十六进制数
			high, low := s[i+1], s[i+2]
			var decoded byte

			// 解析高位
			if high >= '0' && high <= '9' {
				decoded = (high - '0') << 4
			} else if high >= 'A' && high <= 'F' {
				decoded = (high - 'A' + 10) << 4
			} else if high >= 'a' && high <= 'f' {
				decoded = (high - 'a' + 10) << 4
			} else {
				return "", fmt.Errorf("invalid hex digit: %c", high)
			}

			// 解析低位
			if low >= '0' && low <= '9' {
				decoded |= low - '0'
			} else if low >= 'A' && low <= 'F' {
				decoded |= low - 'A' + 10
			} else if low >= 'a' && low <= 'f' {
				decoded |= low - 'a' + 10
			} else {
				return "", fmt.Errorf("invalid hex digit: %c", low)
			}

			// 添加解码后的字节
			result = append(result, decoded)
			i += 2 // 跳过已处理的两个字符
		} else if s[i] == '+' {
			// 将加号替换为空格
			result = append(result, ' ')
		} else {
			// 其他字符直接添加
			result = append(result, s[i])
		}
	}

	// 返回字符串形式的结果
	return string(result), nil
}
