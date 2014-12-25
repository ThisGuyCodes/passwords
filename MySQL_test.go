package passwords

import (
	"testing"
)

const (
	mySQLFail = "Password '%s' encrypted by MySQL should have been '%s'; got '%s'."
)

var (
	validMySQLPasswords = map[string]string{
		"Password1": "*7ee969bbe0a3985c8bff9fa65a06345c67fe434a",
		"password":  "*2470c0c06dee42fd1618bb99005adca2ec9d1e19",
		"recover":   "*71383c96a85618165875eb3f9d9e52179c3291e7",
		"incorrect": "*2f8bcdbfd7618656393be67f7f1d8ccfaa87f8fc",
	}
)

func TestMySQL(t *testing.T) {
	for plain, encrypted := range validMySQLPasswords {
		got := MySQL(plain)
		if encrypted != got {
			t.Fatalf(mySQLFail, plain, encrypted, got)
		}
	}
}

func BenchmarkMySQL(b *testing.B) {
	for i := 0; i < b.N; i++ {
		MySQL("A slightly longer thing to encrypt")
	}
}
