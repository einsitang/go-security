package ctx

type Principal struct {
	Id          string
	Roles       []string
	Permissions []string
	Groups      []string
}

type Context struct {
	Principal *Principal
	Params    map[string]any
}
