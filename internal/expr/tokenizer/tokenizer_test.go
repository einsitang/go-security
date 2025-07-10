package tokenizer

import "testing"

func TestParseToken(t *testing.T) {
	THello := TokenKey(100)
	TWorld := TokenKey(101)
	TRoleKey := TokenKey(105)
	TAndKey := TokenKey(106)

	parser := New()
	// ignore case
	parser.DefineTokens(THello, []string{"hello"}, AloneTokenOption)
	parser.DefineTokens(TRoleKey, []string{"Role"})
	parser.DefineTokens(TWorld, []string{"world"})
	parser.DefineTokens(TAndKey, []string{"and"})
	input := "helloworld can match,but hello is ok ,prefixWorld role and roles both not match,but Role and WorLd is match will"
	stream := parser.ParseString(input)
	for stream.IsValid() {
		token := stream.CurrentToken()
		t.Logf("[%d:%d] %s %v", token.Line(), token.Offset(), token.ValueString(), token.Key())
		stream.GoNext()
	}
}
