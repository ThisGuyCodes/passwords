package passwords

import (
	"testing"
)

const (
	shaCryptFailErr    = "Password '%s$%s' encrypted with ShaCrypt should have no error, got '%s'."
	shaCryptFailResult = "Password '%s' encrypted by ShaCrypt should have been '%s'; got '%s'."
	shaCryptFailNoErr  = "Password '%s' encrypted with ShaCrypt should have produced an error, it did not."
)

type validShaCryptData struct {
	Password  string
	Salt      string
	Encrypted string
}

type invalidShaCryptData struct {
	Password string
	Salt     string
}

var (
	validShaCryptPasswords = []validShaCryptData{
		validShaCryptData{
			Password:  "test",
			Salt:      "saltandd",
			Encrypted: "$6$saltandd$4EB6r9HjiOq0Fu2/kHRJVdUhckKv1EVh4O36u.hLPBsljjn.c47frSzax7kPvrVaFO4Qom4zrYB.y9/wxlDbN.",
		},
		validShaCryptData{
			Password:  "another password",
			Salt:      "moresalt",
			Encrypted: "$6$moresalt$P8Fkg5eFo5MTK8Wor17gSlHnaNR0aK/tVnIvww4MnQvqveR2qXbzZ6J81HCTYoEZT7bNpsj07STCed1HhtQoz/",
		},
	}

	// Password/salt combinations that should produce a non-nil error
	invalidShaCryptPasswords = []invalidShaCryptData{
		invalidShaCryptData{
			Password: "test",
			Salt:     "short",
		},
		invalidShaCryptData{
			Password: "test",
			Salt:     "more than 16 characters",
		},
	}
)

func TestShaCrypt_valid(t *testing.T) {
	for _, data := range validShaCryptPasswords {
		got, err := ShaCrypt(data.Password, data.Salt)
		if err != nil {
			t.Errorf(shaCryptFailErr, data.Password, data.Salt, err)
			// Don't bother with the next check if this failed
			continue
		}
		if got != data.Encrypted {
			t.Errorf(shaCryptFailResult, data.Password, data.Encrypted, got)
			continue
		}
	}
}

func TestShaCrypt_invalid(t *testing.T) {
	for _, data := range invalidShaCryptPasswords {
		_, err := ShaCrypt(data.Password, data.Salt)
		if err == nil {
			t.Errorf(shaCryptFailNoErr, data.Password, data.Salt)
		}
	}
}

func BenchmarkShaCrypt(b *testing.B) {
	data := validShaCryptPasswords[0]

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ShaCrypt(data.Password, data.Salt)
	}
}
