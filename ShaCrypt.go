package passwords

import (
	"crypto/sha512"
	"errors"
	"math/big"
)

const (
	b64String = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	sigBytes  = 86
)

var (
	// we have to re-arrange the hash towards the end, this is the new order (space efficient BECAUSE I CAN)
	newOrder = [64]uint8{
		63, 62, 20, 41, 40, 61, 19, 18, 39, 60, 59, 17, 38, 37, 58, 16, 15, 36, 57, 56, 14, 35,
		34, 55, 13, 12, 33, 54, 53, 11, 32, 31, 52, 10, 9, 30, 51, 50, 8, 29, 28, 49, 7,
		6, 27, 48, 47, 5, 26, 25, 46, 4, 3, 24, 45, 44, 2, 23, 22, 43, 1, 0, 21, 42}
	big63 = big.NewInt(63)
)

// Creates a unix password string using sha512
func ShaCrypt(pass, salt string) (string, error) {
	// Get the length (we need this later)
	passLen := len(pass)
	saltLen := len(salt)

	// Salt must be the right length
	if saltLen < 8 || saltLen > 16 {
		return "", errors.New("arg 2 must be between 8 and 16 bytes long")
	}

	// Create the hasher (unique per instance to be thread safe :D)
	hasher := sha512.New()
	hashLen := hasher.Size()

	// Change to bytes, more naitive
	passByte := []byte(pass)
	saltByte := []byte(salt)

	// Create the 'alternate'
	hasher.Write(passByte)
	hasher.Write(saltByte)
	hasher.Write(passByte)
	alternate := hasher.Sum(nil)
	hasher.Reset()

	// Write the initial password and salt
	hasher.Write(passByte)
	hasher.Write(saltByte)

	// Write one byte of 'alternate' for every byte of the password
	for i := passLen; i != 0; {
		var n int
		if i > hashLen {
			n, _ = hasher.Write(alternate)
		} else {
			n, _ = hasher.Write(alternate[:i])
		}
		i -= n
	}

	// Alternate between the password and the alternate for the length of the password
	for i := passLen; i != 0; i >>= 1 {
		if i&1 == 1 {
			hasher.Write(alternate)
		} else {
			hasher.Write(passByte)
		}
	}

	// Now we have our intermediate :D (re-using variables tho {this is for you gc :3})
	alternate = hasher.Sum(nil)
	hasher.Reset()

	// Get value of the first byte
	firstByte := int(alternate[0])

	// Get first passLen bytes of hash of password repeated passLen times
	for i := 0; i < passLen; i++ {
		hasher.Write(passByte)
	}
	pHash := hasher.Sum(nil)[:passLen]
	hasher.Reset()

	// Get the first saltLen bytes of hash of salt repeated (first byte of pass) + 16 times
	for i := 0; i < firstByte+16; i++ {
		hasher.Write(saltByte)
	}
	sHash := hasher.Sum(nil)[:saltLen]
	// We reset at the start on the next one (to avoid an extra call to reset), so we can skip this one
	//hasher.Reset()

	// Loop 5k times, on some do some things, others do others
	for i := 0; i < 5000; i++ {
		hasher.Reset()
		if i&1 == 1 {
			hasher.Write(pHash)
		} else {
			hasher.Write(alternate)
		}
		if i%3 != 0 {
			hasher.Write(sHash)
		}
		if i%7 != 0 {
			hasher.Write(pHash)
		}
		if i&1 == 1 {
			hasher.Write(alternate)
		} else {
			hasher.Write(pHash)
		}
		alternate = hasher.Sum(nil)
	}
	// Not using this again, so no need to reset
	//hasher.Reset()

	// Now re-arrange the intermediate
	intermediate := make([]byte, hashLen)
	for i, new := range newOrder {
		intermediate[i] = alternate[new]
	}

	// I THINK it's a normal b64 encoding (with the altered order of bytes used, see b64String)
	// but with the order the 6-bits are read reversed. That is if my understanding of b64 encoding
	// is correct. Bellow does what is needed, and very efficiently. I'll look into reversing the
	// order and using the base64 package later.
	asInt := big.NewInt(0)
	asInt.SetBytes(intermediate)
	rem := big.NewInt(0)
	realPass := make([]byte, sigBytes)
	for i := 0; i < sigBytes; i++ {
		rem.And(asInt, big63)
		realPass[i] = b64String[rem.Int64()]
		asInt.Rsh(asInt, 6)
	}

	// Done!
	return "$6$" + salt + "$" + string(realPass), nil
}
