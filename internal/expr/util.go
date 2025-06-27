package expr

import (
	"fmt"
	"reflect"
	"strings"

	syntax "github.com/einsitang/go-security/internal/expr/snytax"
)

func DebugAst(st *SyntaxTree) {
	if st.Syntax == nil {
		fmt.Println("empty tree")
		return
	}

	printTreeNode(st.Syntax, 0)
}

func printTreeNode(node syntax.Syntax, ident int) {
	if node == nil {
		return
	}

	typeName := reflect.TypeOf(node).String()
	typeKind := node.Kind()
	typePriority := node.Priority()

	fmt.Printf("%s :Node: %s, Type: %d, Priority: %d\n", strings.Join(make([]string, ident), " "), typeName, typeKind, typePriority)

	switch typeKind {
	case 1:
		printTreeNode(node.Left(), ident+1)
	case 2:
		printTreeNode(node.Left(), ident+1)
		printTreeNode(node.Right(), ident+1)
	}
}
