package ctx

type Principal interface {
	Id() string
	Roles() []string
	Permissions() []string
	Groups() []string
}
type Context struct {
	Principal    Principal
	Params       map[string]any
	CustomParams map[string]any
}
