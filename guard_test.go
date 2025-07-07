package security

import "testing"

func BenchmarkGuard(b *testing.B) {
	guard, err := NewGuard("allow:Role('admin') and $age >= 18 - 9")
	if err != nil {
		b.Error(err)
		return
	}

	var checked bool
	for i := 0; i < b.N; i++ {
		checked, err = guard.Check(&SecurityContext{
			Principal: &principal{
				roles: []string{"admin"},
			},
			Params: map[string]any{
				"type": "user",
				"age":  "19",
			},
		})
	}

	if err != nil {
		b.Logf("err: %v", err)
	} else {
		b.Logf("N(%d) checked:%v", b.N, checked)
	}
}

func TestGuard(t *testing.T) {
	guard, err := NewGuard("allow:Role('admin') and $age >= 18 - 9")
	if err != nil {
		t.Error(err)
		return
	}
	check, err := guard.Check(&SecurityContext{
		Principal: &principal{
			roles: []string{"admin"},
		},
		Params: map[string]any{
			"type": "user",
			"age":  "19",
		},
	})

	if err != nil {
		t.Logf("err: %v", err)
	} else {
		t.Log("check", check)
	}
}
