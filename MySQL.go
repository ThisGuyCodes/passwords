package passwords

import (
	"encoding/hex"
	"hash"
)

// Passwords for MySql
func MySQL(pass string) string {
	// Get our own hasher, for thread safety
	hasher := sha1Pool.Get().(hash.Hash)
	// Back to the pool! (later)
	defer sha1Pool.Put(hasher)

	// We cannot assume the hasher from the pool is clean
	hasher.Reset()

	// This is actually really simple, it's just a sha1 of a sha1 displayed as hex
	// (with a leading * to indicate the 'new' password hash of MySql)
	hasher.Write([]byte(pass))
	interm := hasher.Sum(nil)
	hasher.Reset()
	hasher.Write(interm)

	return "*" + hex.EncodeToString(hasher.Sum(nil))
}
