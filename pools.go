package passwords

import (
	"crypto/sha1"
	"crypto/sha512"
	"sync"
)

// This block contains various pools for resources we constantly need; mosty hashers and encoders.
var (
	sha1Pool = sync.Pool{
		New: sha1New,
	}
	sha512Pool = sync.Pool{
		New: sha512New,
	}
)

func sha1New() interface{} {
	return sha1.New()
}

func sha512New() interface{} {
	return sha512.New()
}
