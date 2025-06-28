package security

import "testing"

func TestGuard(t *testing.T) {
	guard, err := NewGuard("allow:Role('admin') and $type == 'user'")
	if err != nil {
		t.Error(err)
		return
	}
	check := guard.Check(&SecurityContext{
		Principal: &principal{
			roles: []string{"admin"},
		},
		Params: map[string]any{
			"type": "user",
		},
	})

	t.Log("check", check)
}
