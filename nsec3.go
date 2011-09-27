package dns

import (
	"io"
	"hash"
	"strings"
	"crypto/sha1"
	"os"
)

type saltWireFmt struct {
	Salt string "size-hex"
}

// HashName hashes a string or a name according to RFC5155. It returns
// the hashed string.
func HashName(label string, ha uint8, iterations uint16, salt string) string {
	saltwire := new(saltWireFmt)
	saltwire.Salt = salt
	wire := make([]byte, DefaultMsgSize)
	n, ok := packStruct(saltwire, wire, 0)
	if !ok {
		return ""
	}
	wire = wire[:n]
	name := make([]byte, 255)
	off, ok1 := packDomainName(strings.ToLower(label), name, 0)
	if !ok1 {
		return ""
	}
	name = name[:off]
	var s hash.Hash
	switch ha {
	case 0: // NSEC4 - no hashing
		return label
	case SHA1:
		s = sha1.New()
	default:
		return ""
	}

	// k = 0
	name = append(name, wire...)
	io.WriteString(s, string(name))
	nsec3 := s.Sum()
	// k > 0
	for k := 0; k < int(iterations); k++ {
		s.Reset()
		nsec3 = append(nsec3, wire...)
		io.WriteString(s, string(nsec3))
		nsec3 = s.Sum()
	}
	return unpackBase32(nsec3)
}

// NextCloser constructs the next closer name from the closest encloser
// and returns it.
func NextCloser(qname, ce string) string {
	ql := LabelSliceReverse(strings.Split(qname, "."))
	match := ""

	// Match until it doesn't match anymore, the previous
	// match is the label we should add to the closest encloser
	// to get the next closer
	// root label goed wrong here
	for i, l := range LabelSliceReverse(strings.Split(ce, ".")) {
		if ql[i] == l {
			match = l
		} else {
			break
		}
	}
	if len(match) == 0 {
		return ""
	}
	return match + "." + ce
}

// CoversName returns true when the name falls in the
// interval specified by <ownername .. nextname>, exclusive.
// If ownername (or name?) contains a dot a non-hashed matched is
// assumed (NSEC), if does not, we do a NSEC3/NSEC4 match.
func CoversName(name, ownername, nextname string) bool {
	// strings.Index should be something DNS specific
	// that knows the escaping of names
	switch strings.Index(ownername, ".") {
	case -1:
		// NSEC3/4 match
		return strings.ToUpper(ownername) < strings.ToUpper(name) && strings.ToUpper(name) < strings.ToUpper(nextname)
	default:
		return false
	}
	panic("not reached")
	return false
}

// Hash the ownername and the next owner name in an NSEC3 record according
// to RFC 5155.
// Use the parameters from the NSEC3 itself.
func (nsec3 *RR_NSEC3) HashNames() {
	nsec3.Header().Name = HashName(nsec3.Header().Name, nsec3.Hash, nsec3.Iterations, nsec3.Salt)
	nsec3.NextDomain = HashName(nsec3.NextDomain, nsec3.Hash, nsec3.Iterations, nsec3.Salt)
}

// NsecVerify verifies the negative response (NXDOMAIN/NODATA) in 
// the message m. 
// NsecVerify returns nil when the NSECs in the message contain
// the correct proof. This function does not validates the NSECs
func (m *Msg) NsecVerify(q Question) os.Error {

	return nil
}

// Nsec3Verify verifies ...
func (m *Msg) Nsec3Verify(q Question) os.Error {

	return nil
}
