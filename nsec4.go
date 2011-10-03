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
	if len(m.Answer) > 0 && len(m.Ns) > 0 {
		// Wildcard expansion
		// Closest encloser inferred from SIG in authority and qname
		println("EXPANDED WILDCARD PROOF or DNAME CNAME")
		println("NODATA")
		// I need to check the type bitmap
		// wildcard bit not set?
		// MM: No need to check the wildcard bit here:
		//     This response has only 1 NSEC4 and it does not match
		//     the closest encloser (it covers next closer).
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
		suffix := "" // Not need for Zero hashing
		if algo != 0 {
			// 2nd name is the zone name
			suffix = "." + strings.ToUpper((LabelSlice(nsec4[0].(*RR_NSEC4).NextDomain))[1])
		}

		// One of these NSEC4s MUST match the closest encloser.
		ce := "goed.fout."
	ClosestEncloser:
		for _, nsec := range nsec4 {
			for _, ce1 := range LabelSlice(q.Name) {
				println("H:", HashName(ce1, algo, iter, salt)+suffix)
				println("N:", strings.ToUpper(nsec.Header().Name))
				if HashName(ce1, algo, iter, salt)+suffix == strings.ToUpper(nsec.Header().Name) {
					ce = ce1
					break ClosestEncloser
				}
			}
		}
		if ce == "goed.fout." {
			// If we didn't find the closest here, we have a NODATA wilcard response
			println("CE NIET GEVONDEN")
			println(" (WILDCARD) NODATA RESPONSE")
			// chop the qname, append the wildcard label, and see it we have a match
			// Zijn we nog wel in de zone bezig als we deze antwoord hebben
			// dat moeten we toch wel controleren TODO(MG)
			// MM: source-of-synthesis (source) = *.closest-encloser (ce)
			// 1. ce is an ancestor of QNAME of which source is matched by an
			// NSEC4 RR present in the response.
			// 2. The name one label longer than ce (but still an ancestor of --
			// or equal to -- QNAME) is covered by an NSEC4 RR present in the
			// response.
			// 3. Are the NSEC4 RRs from the proper zone?
			// The NSEC4 that matches the wildcard RR is: 
			// Check that the signer field in the RRSIG on both NSEC4 RRs
			// is the same. If so, both NSEC4 RRs are from the same zone.

		Synthesis:
			for _, nsec := range nsec4 {
				for _, ce1 := range LabelSlice(q.Name) {
					source := "*." + ce1
					if ce1 == "." {
						source = "*."

					}
					println(source, ":", HashName(source, algo, iter, salt))
					println("               : ", strings.ToUpper(nsec.Header().Name))
					if HashName(source, algo, iter, salt)+suffix == strings.ToUpper(nsec.Header().Name) {
						ce = ce1
						break Synthesis
					}
				}
			}
			println("Source of synthesis found, CE = ", ce)
			// Als niet gevonden, shit hits the fan?!
			// MM: je hebt nog niet de gewone NODATA geprobeerd...
			if ce == "goed.fout." {
				println("Source of synth not found")
			}
		}

		// if q.Name == ce -> Check nodata, wildcard flag off	
		if strings.ToUpper(q.Name) == strings.ToUpper(ce) {
			println("WE HAVE TO DO A NODATA PROOF 2")
                        for _, nsec := range nsec4 {
                                println(HashName(ce, algo, iter, salt)+suffix, strings.ToUpper(nsec.Header().Name))
                                if HashName(ce, algo, iter, salt)+suffix == strings.ToUpper(nsec.Header().Name) {
                                        fmt.Printf("We should not have the type? %v\n", !bitmap(nsec.(*RR_NSEC4), q.Qtype))
                                        if !bitmap(nsec.(*RR_NSEC4), q.Qtype) {
                                                println("NODATA IS PROVEN, IF NSEC4S ARE VALID")
                                        }
                                        return nil

                                }
                        }
			println("CHECK TYPE BITMAP 2")
			return nil
		}

		nc := NextCloser(q.Name, ce)

		println("Clostest encloser found:", ce, HashName(ce, algo, iter, salt))
		println("Next closer:", nc)
		// One of these NSEC4s MUST cover the next closer


		println("NEXT CLOSER PROOF")
	NextCloser:
		for _, nsec := range nsec4 {
			// NSEC-like, whole name
			println(nc)
			println(strings.ToUpper(HashName(nc, algo, iter, salt)))
			println(nsec.Header().Name)
			println(nsec.(*RR_NSEC4).NextDomain)

			// NSEC3/NSEC4-like, the first label only NOT NEEDED
			println(nc, "Hashed:", strings.ToUpper(HashName(nc, algo, iter, salt))+suffix)
			println(nsec.Header().Name)
			println(nsec.(*RR_NSEC4).NextDomain)
			if CoversName(HashName(nc, algo, iter, salt), nsec.Header().Name, nsec.(*RR_NSEC4).NextDomain) {
				// Wildcard bit must be off
				println("* covers *")
				if nsec.(*RR_NSEC4).Flags&WILDCARD == 1 {
					println("Wildcard set! Error")
					println("NOT PROVEN NXDOMAIN")
				} else {
					println("Wildcard not set")
					println("NXDOMAIN IS PROVEN, IF NSEC4S ARE VALID")
					break NextCloser
				}
			}
		}
		// If the nextcloser MATCHES the owername of one of the NSEC4s we have a NODATA response

	}
	return nil
}

func bitmap(n *RR_NSEC4, needle uint16) bool {
	for _, t := range n.TypeBitMap {
		if t == needle {
			return true
		}
                if t > needle {
                        return false
                }
	}
        return false
}
