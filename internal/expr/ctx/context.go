package ctx

type Principal interface {
	Id() string
	Roles() []string
	Permissions() []string
	Groups() []string
}
type Context struct {
	// "当事人"
	Principal Principal

	// endpoint 参数
	Params map[string]any

	// 自定义参数
	CustomParams map[string]string
}
