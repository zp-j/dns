package dns

import (
	"fmt"
	"os"
	"strings"
)

// Nsec3Verify verifies an denial of existence response.
// It needs to original query and the reply message.
// Returns nil when ok, otherwise error indicating what the
// problem is.
func (m *Msg) Nsec4Verify(q Question) os.Error {
	if len(m.Answer) == 0 && len(m.Ns) > 0 {
		// Maybe an NXDOMAIN
		nsec4 := SieveRR(m.Ns, TypeNSEC4)
                if len(nsec4) == 0 {
                        println("Nie goed")
                        return nil
                }
                algo := nsec4[0].(*RR_NSEC4).Hash
                iter := nsec4[0].(*RR_NSEC4).Iterations
                salt := nsec4[0].(*RR_NSEC4).Salt

		// One of these NSEC4s MUST match the closest encloser
                for _, ce := range LabelSlice(q.Name) {
                        fmt.Printf("%v %v\n", ce, strings.ToLower(HashName(ce, algo, iter, salt)))
                }

	}
	return nil
}
