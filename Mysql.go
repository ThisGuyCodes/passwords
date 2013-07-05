package passwords

import (
	"crypto/sha1"
	"encoding/hex"
)

// Passwords for MySql
func Mysql(pass string) string {
	// Create our own hasher, for thread safety
	hasher := sha1.New()
	// This is actually really simple, it's just a sha1 of a sha1 displayed as hex
	// (with a leading * to indicate the 'new' password hash of MySql)
	hasher.Write([]byte(pass))
	interm := hasher.Sum(nil)
	hasher.Reset()
	hasher.Write(interm)
	return "*" + hex.EncodeToString(hasher.Sum(nil))
}
