package dns

// PrivateRR implementation.
// Allows one took hook private RR (RFC XXXX) into this package and have
// them function like the normal RR already there.

// Lexer holds the lexer state when parsing a private RR.
type Lexer struct {
	c chan lex
	l lex
}

const (
	Eof = iota
	String
	Space
	Newline
	Quote
)

// Next will read the next token from the Lexer when parsing a private RR.
func (x *Lexer) Next() {
	t := <-x.c
	x.l = t
}

// Token returns the token from x. Note the token must first be read with x.Next().
func (x *Lexer) Token() string { return x.l.token }

// TokenUpper returns the uppercase version of the token from x.
func (x *Lexer) TokenUpper() string { return x.l.tokenUpper }

// Length locate the length of the token string.
func (x *Lexer) Length() int { return x.l.length }

// Comment returns the associated comment from the Lexer.
func (x *Lexer) Comment() string { return x.l.comment }

// NewParseError creates a new ParseError from the Lexer.
func (x *Lexer) NewParseError(err error) *ParseError { return &ParseError{err: err.Error(), lex: x.l} }

// Value returns the value of the token from the lexer. The are a couple of importante values
// that can be returned: String, Space, Quote, Newline or Eof.
func (x *Lexer) Value() int {
	switch x.l.value {
	case _STRING:
		return String
	case _BLANK:
		return Space
	case _NEWLINE:
		return Newline
	case _QUOTE:
		return Quote
	case _EOF:
		return Eof
	}
	return 0 // TODO(miek: What to do here.
}
