// Package main provides ...
package main

import (
	"dns"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	// Detected software types
	NSD        = "NSD"
	BIND       = "BIND"
	POWERDNS   = "PowerDNS"
	WINDOWSDNS = "Windows DNS"
	MARADNS    = "MaraDNS"
	NEUSTARDNS = "Neustar DNS"
	ATLAS      = "Atlas"

	// Vendors
	ISC       = "ISC"
	MARA      = "MaraDNS.org" // check
	NLNETLABS = "NLnet Labs"
	MICROSOFT = "Microsoft"
	POWER     = "PowerDNS.com"
	NEUSTAR   = "Neustar"
	VERISIGN  = "Verisign"
)

func startParse(addr string) {
	l := &lexer{
		addr:   addr,
		client: dns.NewClient(),
		fp:     new(fingerprint),
		items:  make(chan item),
		state:  dnsAlive,
		debug:  true,
	}

	l.run()

	// Not completely sure about this code..
	for {
		item := <-l.items
		fmt.Printf("{%s %s}\n", itemString[item.typ], item.val)
		if l.state == nil {
			break
		}
	}
}

// SendProbe creates a packet and sends it to the nameserver. It
// returns a fingerprint.
func sendProbe(c *dns.Client, addr string, f *fingerprint) *fingerprint {
	m := f.toProbe()
	r, err := c.Exchange(m, addr)
	if err != nil {
		return errorToFingerprint(err)
	}
	return msgToFingerprint(f,r)
}

// This leads to strings like: "miek.nl.,IN,A,QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,1,DO,4096,NSID,miek.nl.,IN,A"
// Or "miek.nl.,IN,A,QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,1,DO,4096,NSID,,,", where to reply is empty
type fingerprint struct {
	Query              dns.Question // Question to ask
	Error              os.Error
	Opcode             int
	Rcode              int
	Response           bool
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	Zero               bool
	Question           int
	Answer             int
	Ns                 int
	Extra              int
	Do                 bool
	UDPSize            int
	Nsid               bool
	Reply              dns.Question // Question section from the reply
}

// String creates a (short) string representation of a dns message.
// If a bit is set we uppercase the name 'AD' otherwise it's lowercase 'ad'.
// This leads to strings like: "QUERY,NOERROR,qr,aa,tc,RD,ad,cd,z,1,0,0,1,DO,4096,NSID" // TODO fix doc
func (f *fingerprint) String() string {
	if f == nil {
		return "<nil>"
	}
	// Use the same order as in Perl's fpdns. But use much more flags.

        // The Question.
        s := f.Query.Name
        s += "," + dns.Class_str[f.Query.Qclass]
        if _, ok := dns.Rr_str[f.Query.Qtype]; ok {
                s += "," + dns.Rr_str[f.Query.Qtype]
        } else {
                s += "," + "TYPE" + strconv.Itoa(int(f.Query.Qtype))
        }


	if op, ok := dns.Opcode_str[f.Opcode]; ok {
		s += "," + op
	} else { // number
		s += "," + valueOfInt(f.Opcode)
	}

	if op, ok := dns.Rcode_str[f.Rcode]; ok {
		s += "," + op
	} else { // number
		s += "," + valueOfInt(f.Rcode)
	}

	s += valueOfBool(f.Response, ",qr")
	s += valueOfBool(f.Authoritative, ",aa")
	s += valueOfBool(f.Truncated, ",tc")
	s += valueOfBool(f.RecursionDesired, ",rd")
	s += valueOfBool(f.RecursionAvailable, ",ra")
	s += valueOfBool(f.AuthenticatedData, ",ad")
	s += valueOfBool(f.CheckingDisabled, ",cd")
	s += valueOfBool(f.Zero, ",z")

	s += "," + valueOfInt(f.Question)
	s += "," + valueOfInt(f.Answer)
	s += "," + valueOfInt(f.Ns)
	s += "," + valueOfInt(f.Extra)

	s += valueOfBool(f.Do, ",do")
	s += "," + valueOfInt(f.UDPSize)
	s += valueOfBool(f.Nsid, ",nsid")

        // A possible reply
        s += "," + f.Reply.Name
        s += "," + dns.Class_str[f.Reply.Qclass]
        if _, ok := dns.Rr_str[f.Reply.Qtype]; ok {
                s += "," + dns.Rr_str[f.Reply.Qtype]
        } else {
                s += "," + "TYPE" + strconv.Itoa(int(f.Reply.Qtype))
        }
	return s
}

// fingerStringNoSections returns the strings representation
// without the sections' count and the EDNS0 stuff
func (f *fingerprint) StringNoSections() string {
	s := strings.SplitN(f.String(), ",", 11)
	return strings.Join(s[:10], ",")
}

// SetString set the string to fp.. todo
func (f *fingerprint) setString(str string) {
	for i, s := range strings.Split(str, ",") {
		switch i {
                        // 3 added before
		case 0:
			if op, ok := dns.Str_opcode[s]; ok {
				f.Opcode = op
			} else { // number
				f.Opcode = valueOfString(s)
			}
		case 1:
			if op, ok := dns.Str_rcode[s]; ok {
				f.Rcode = op
			} else { // number
				f.Rcode = valueOfString(s)
			}
		case 2:
			f.Response = s == strings.ToUpper("qr")
		case 3:
			f.Authoritative = s == strings.ToUpper("aa")
		case 4:
			f.Truncated = s == strings.ToUpper("tc")
		case 5:
			f.RecursionDesired = s == strings.ToUpper("rd")
		case 6:
			f.RecursionAvailable = s == strings.ToUpper("ra")
		case 7:
			f.AuthenticatedData = s == strings.ToUpper("ad")
		case 8:
			f.CheckingDisabled = s == strings.ToUpper("cd")
		case 9:
			f.Zero = s == strings.ToUpper("z")
		case 10, 11, 12, 13:
			// Can not set lenght of the section in the message
		case 14:
			f.Do = s == strings.ToUpper("do")
		case 15:
			f.UDPSize = valueOfString(s)
		case 16:
			f.Nsid = s == strings.ToUpper("nsid")
                // add 3 extra for reply message
                // If all nil, dont set
		default:
			panic("unhandled fingerprint")
		}
	}
	return
}

func (f *fingerprint) ok() bool {
	return f.Error == nil
}

func (f *fingerprint) error() string {
	if f.Error == nil {
		panic("error is nil")
	}
	return f.Error.String()
}

func errorToFingerprint(e os.Error) *fingerprint {
	f := new(fingerprint)
	f.Error = e
	return f
}

func msgToFingerprint(f *fingerprint,m *dns.Msg) *fingerprint {
	if m == nil {
		return nil
	}
	h := m.MsgHdr
	f1 := new(fingerprint)

        // Set the old query
        f1.Query.Name = f.Query.Name
        f1.Query.Qtype = f.Query.Qtype
        f1.Query.Qclass = f.Query.Qclass

	f1.Opcode = h.Opcode
	f1.Rcode = h.Rcode
	f1.Response = h.Response
	f1.Authoritative = h.Authoritative
	f1.Truncated = h.Truncated
	f1.RecursionDesired = h.RecursionDesired
	f1.RecursionAvailable = h.RecursionAvailable
	f1.AuthenticatedData = h.AuthenticatedData
	f1.CheckingDisabled = h.CheckingDisabled
	f1.Zero = h.Zero

	f1.Question = len(m.Question)
	f1.Answer = len(m.Answer)
	f1.Ns = len(m.Ns)
	f1.Extra = len(m.Extra)
	f1.Do = false
	f1.UDPSize = 0

        // Set the reply answer section
        if len(m.Answer) > 0 {
                f1.Reply.Name = m.Question[0].Name
                f1.Reply.Qtype = m.Question[0].Qtype
                f1.Reply.Qclass = m.Question[0].Qclass
        } else {
                f1.Reply.Name = "."
                f1.Reply.Qtype = 0
                f1.Reply.Qclass = 0
        }

	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			// version is always 0 - and I cannot set it anyway
			f1.Do = r.(*dns.RR_OPT).Do()
			f1.UDPSize = int(r.(*dns.RR_OPT).UDPSize())
			if len(r.(*dns.RR_OPT).Option) == 1 {
				// Only support NSID atm
				f1.Nsid = r.(*dns.RR_OPT).Option[0].Code == dns.OptionCodeNSID
			}
		}
	}
	return f1
}

// Create a dns message from a fingerprint string and
// a DNS question. The order of a string is always the same.
// QUERY,NOERROR,qr,aa,tc,RD,ad,ad,z,1,0,0,1,DO,4096,nsid
func (f *fingerprint) toProbe() *dns.Msg {
	m := new(dns.Msg)
	m.MsgHdr.Id = dns.Id()
//	m.Question = make([]dns.Question, 1)
        m.Question[0] = dns.Question{f.Query.Name, f.Query.Qtype, f.Query.Qclass}
	m.MsgHdr.Opcode = f.Opcode
	m.MsgHdr.Rcode = f.Rcode
	m.MsgHdr.Response = f.Response
	m.MsgHdr.Authoritative = f.Authoritative
	m.MsgHdr.Truncated = f.Truncated
	m.MsgHdr.RecursionDesired = f.RecursionDesired
	m.MsgHdr.AuthenticatedData = f.AuthenticatedData
	m.MsgHdr.CheckingDisabled = f.CheckingDisabled
	m.MsgHdr.Zero = f.Zero

	if f.Do {
		// Add an OPT section.
		m.SetEdns0(0, true)
		// We have added an OPT RR, set the size.
		m.Extra[0].(*dns.RR_OPT).SetUDPSize(uint16(f.UDPSize))
		if f.Nsid {
			m.Extra[0].(*dns.RR_OPT).SetNsid("")
		}
	}
	return m
}

func valueOfBool(b bool, w string) string {
	if b {
		return strings.ToUpper(w)
	}
	return strings.ToLower(w)
}

func valueOfInt(i int) string {
	return strconv.Itoa(i)
}

func valueOfString(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
