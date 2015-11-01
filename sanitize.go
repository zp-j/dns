package dns

// Dedup removes identical RRs from rrs. It preserves the original ordering.
// The lowest TTL of any duplicates is used in the remaining one. Dedup modifies
// rrs.
// m is used to store the RRs temporay. If it is nil a new map will be allocated.
func Dedup(rrs []RR, m map[string]RR) []RR {
	if m == nil {
		m = make(map[string]RR)
	}
	// Save the keys, so we don't have to call normalizedString twice.
	keys := make([]*string, 0, len(rrs))

	for _, r := range rrs {
		key := normalizedString(r)
		keys = append(keys, &key)
		if _, ok := m[key]; ok {
			// Shortest TTL wins.
			if m[key].Header().Ttl > r.Header().Ttl {
				m[key].Header().Ttl = r.Header().Ttl
			}
			continue
		}

		m[key] = r
	}
	// If the length of the result map equals the amount of RRs we got,
	// it means they were all different. We can then just return the original rrset.
	if len(m) == len(rrs) {
		return rrs
	}

	j := 0
	for i, r := range rrs {
		// If keys[i] lives in the map, we should copy and remove it.
		if _, ok := m[*keys[i]]; ok {
			delete(m, *keys[i])
			rrs[j] = r
			j++
		}

		if len(m) == 0 {
			break
		}
	}

	return rrs[:j]
}

// Sort sorts the RRs in rrs. It will:
//
// * Sort CNAME chains in their chaining order: b->c, a->b, becomes: a->b, b->c
//
func Sort(rrs []RR) []RR {
	return rrs
}

// Fit will make m fit the size. If a message is larger than size the entire
// additional section is dropped. If it is still too large and net
// is "udp", "udp4" or "udp6" we return a truncated message.
// TODO(miek): smartness wrt to DNSSEC signatures and delegations (we can't drop everything
// in the add. section because we might need it for the delegation to work)
//
// If net is "tcp", "tcp4" or "tcp6" we are going to drop RR from the answer section
// until it fits. When this is case the returned bool is true.
// TODO(miek): not sure I want this behavoir for tcp.
func Fit(m *Msg, size int, net string) (*Msg, bool) {
	return nil, false
}

// normalizedString returns a normalized string from r. The TTL
// is removed and the domain name is lowercased. We go from this:
// DomainName<TAB>TTL<TAB>CLASS<TAB>TYPE<TAB>RDATA to:
// lowercasename<TAB>CLASS<TAB>TYPE...
func normalizedString(r RR) string {
	// A string Go DNS makes has: domainname<TAB>TTL<TAB>...
	b := []byte(r.String())

	// find the first non-escaped tab, then another, so we capture where the TTL lives.
	esc := false
	ttlStart, ttlEnd := 0, 0
	for i := 0; i < len(b) && ttlEnd == 0; i++ {
		switch {
		case b[i] == '\\':
			esc = !esc
		case b[i] == '\t' && !esc:
			if ttlStart == 0 {
				ttlStart = i
				continue
			}
			if ttlEnd == 0 {
				ttlEnd = i
			}
		case b[i] >= 'A' && b[i] <= 'Z' && !esc:
			b[i] += 32
		default:
			esc = false
		}
	}

	// remove TTL.
	copy(b[ttlStart:], b[ttlEnd:])
	cut := ttlEnd - ttlStart
	return string(b[:len(b)-cut])
}
