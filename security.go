package security

type securityContext struct {
	config string
}

type Security interface {
	AddEndpoint(endpoint string, expre string) error
	RemoveEndpoint(endpoint string)
	CleanEndpoints()
}

func New() {

}

// func NewFromConfig(config string) (Security, error) {
// 	// 解析配置并创建 Security 实例
// 	security := &securityContext{
// 		config: config,
// 	}
// 	return security, nil
// }
