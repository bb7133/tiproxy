// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package factor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// The observable instant must also drive the Go expiry branch. These callsite
// checks accompany the behavioral Go/Rust oracle and prevent a second hidden
// time.Since/Now read from escaping the ordered tape.
func TestNativeSingleExpiryInstant(t *testing.T) {
	for _, file := range []string{"factor_cpu.go", "factor_memory.go", "factor_health.go"} {
		_, source, _, ok := runtime.Caller(0)
		require.True(t, ok)
		tree, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(source), file), nil, 0)
		require.NoError(t, err)
		found := false
		for _, decl := range tree.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || function.Name.Name != "UpdateScore" {
				continue
			}
			found = true
			now, since, captured, sub := 0, 0, 0, 0
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if object, ok := selector.X.(*ast.Ident); ok {
					if object.Name == "time" && selector.Sel.Name == "Now" {
						now++
					}
					if object.Name == "time" && selector.Sel.Name == "Since" {
						since++
					}
					if object.Name == "expiryNow" && selector.Sel.Name == "Sub" {
						sub++
					}
				}
				if selector.Sel.Name == "clock" && len(call.Args) == 2 {
					if arg, ok := call.Args[1].(*ast.Ident); ok && arg.Name == "expiryNow" {
						captured++
					}
				}
				return true
			})
			require.Equal(t, []int{1, 0, 1, 1}, []int{now, since, captured, sub}, "NATIVE_SINGLE_EXPIRY_INSTANT %s", file)
		}
		require.True(t, found)
	}
}
