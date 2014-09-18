package dns

// PrivateRR implementation.
// Allows one took hook private RR (RFC XXXX) into this package and have
// them function like the normal RR already there.

type PrivateRR interface {
	// Header returns the header of an resource record. The header contains
	// everything up to the rdata.
	Header() *RR_Header
	// String returns the text representation of the resource record.
	String() string
	// Copy returns a copy of the RR
	Copy() RR
	// len returns the length (in octects) of the uncompressed RR in wire format.
	Len() int
}
