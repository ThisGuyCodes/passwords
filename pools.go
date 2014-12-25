package passwords

import (
	"crypto/sha1"
	"sync"
)

// This block contains various pools for resources we constantly need; mosty hashers and encoders.
var (
	sha1Pool = sync.Pool{
		New: sha1New,
	}
)

func sha1New() interface{} {
	return sha1.New()
}
