// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SIG(0)
//
// From RFC 2931:
//
//     SIG(0) provides protection for DNS transactions and requests ....
//     ... protection for glue records, DNS requests, protection for message headers
//     on requests and responses, and protection of the overall integrity of a response.
//
//
package dns

// The problem here is that if we don't return a []byte, but just a SIG we
// need to pack the message twice when we finally send it

// Sign signs a dns.Msg it fills the signature data with the appropriate data.
// The SIG records should have the SignerNam, KeyTag, Algorithm, Inception
// and expiration set.
func (rr *SIG) Sign(k PrivateKey, m *Msg) ([]byte, error) {
	if k == nil {
		return nil, ErrPrivKey
	}
	if rr.KeyTag == 0 || len(rr.SignerName) == 0 || rr.Algorithm == 0 {
		return nil, ErrKey
	}
	rr.Header().Class = ClassANY
	rr.Header().Ttl = 0
	rr.Header().Name = "."
	rr.OrigTtl = 0
	rr.TypeCovered = 0
	rr.Labels = 0

//	signdata, err := m.Pack()
//	if err != nil {
//		return nil, err
//	}
	// copy the sigwire stuff from dnssec.go
	return nil, nil
}

// SIG0Verify will bla bla
func (rr *SIG) Verify(k *KEY, buf []byte) error {
	return nil
}
