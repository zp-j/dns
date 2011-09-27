package dns

import (
	"os"
	"strings"
)

// Nsec3Verify verifies an denial of existence response.
// It needs to original query and the reply message.
// Returns nil when ok, otherwise error indicating what the
// problem is.
func (m *Msg) Nsec4Verify(q Question) os.Error {
        if len(m.Answer) > 0 && len(m.Ns) > 0 {
                // Wildcard expansion
                // Closest encloser inferred from SIG in authority and qname
                println("EXPANDED WILDCARD PROOF")
                // wildcard bit not set?
        }


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

		// One of these NSEC4s MUST match the closest encloser.
                ce := "goed.fout."
ClosestEncloser:
                for _, nsec := range nsec4 {
                        for _, ce1 := range LabelSlice(q.Name) {
                                switch algo {
                                case 0:
                                        // NSEC-like, the whole name
                                        if HashName(ce1, algo, iter, salt)== strings.ToUpper(nsec.Header().Name) {
                                                ce = ce1
                                                break ClosestEncloser
                                        }
                                default:
                                        // NSEC3/NSEC4-like, the first label only
                                        if HashName(ce1, algo, iter, salt) == strings.ToUpper(Labels(nsec.Header().Name,0)) {
                                                ce = ce1
                                                break ClosestEncloser
                                        }
                                }
                        }
                }
                nc := NextCloser(q.Name, ce)
                // If we didn't find the closest isn't found here, we have a NODATA wilcard response

                println("Clostest encloser found:", ce, HashName(ce, algo, iter, salt))
                println("Next closer:", nc)
                // One of these NSEC4s MUST cover the next closer

                // if q.Name == ce -> Check nodata, wildcard flag off
                if strings.ToUpper(q.Name) == strings.ToUpper(ce) {
                        println("WE HAVE TO DO A NODATA PROOF")
                }

                println("NEXT CLOSER PROOF")
NextCloser:
                for _, nsec := range nsec4 {
                        switch algo {
                        case 0:
                                // NSEC-like, whole name
                                println(nc)
                                println(strings.ToUpper(HashName(nc, algo, iter, salt)))
                                println(nsec.Header().Name)
                                println(nsec.(*RR_NSEC4).NextDomain)

                        default:
                                // NSEC3/NSEC4-like, the first label only
                                println(nc)
                                println(strings.ToUpper(HashName(nc, algo, iter, salt)))
                                println(nsec.Header().Name)
                                println(nsec.(*RR_NSEC4).NextDomain)
                                if CoversName(strings.ToUpper(HashName(nc, algo, iter, salt)), Labels(nsec.Header().Name,0), Labels(nsec.(*RR_NSEC4).NextDomain,0)) {
                                        // Wildcard bit must be off
                                        println("Covers")
                                        if nsec.(*RR_NSEC4).Flags & WILDCARD == 1 {
                                                println("Wildcard set! Error")
                                        } else {
                                                println("Wildcard not set")
                                                break NextCloser
                                        }
                                }

                        }
                }
        // If the nextcloser MATCHES the owername of one of the NSEC4s we have a NODATA response



	}
	return nil
}
