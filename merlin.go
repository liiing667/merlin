package merlin

import (
	"encoding/binary"
	"errors"

	"github.com/mimoo/StrobeGo/strobe"
)

const (
	merlinProtocolLabel  = "Merlin v1.0"
	domainSeparatorLabel = "dom-sep"

	// maxFrameLength is the largest length representable in a Merlin v1
	// length frame, which is a little-endian uint32.
	maxFrameLength = 1<<32 - 1
)

// Lengths that do not fit the Merlin v1 uint32 frame are rejected instead
// of being silently truncated, which would make distinct lengths frame as
// identical prefixes.
var (
	// ErrMessageTooLong is returned when a message is longer than the
	// uint32 length frame can represent.
	ErrMessageTooLong = errors.New("merlin: message length exceeds uint32 frame")

	// ErrChallengeTooLong is returned when a requested challenge length is
	// negative or longer than the uint32 length frame can represent.
	ErrChallengeTooLong = errors.New("merlin: challenge length exceeds uint32 frame")
)

// A Transcript is a Merlin v1 Fiat-Shamir transcript built on top of STROBE.
//
// Each Transcript owns its own STROBE state, so separate transcripts are
// fully independent of one another and may be used concurrently from
// different goroutines. A single Transcript is not safe for concurrent use.
type Transcript struct {
	s strobe.Strobe
}

func NewTranscript(appLabel string) *Transcript {
	t := &Transcript{
		s: strobe.InitStrobe(merlinProtocolLabel, 128),
	}

	// The application label is framed as the message of the domain
	// separation operation. A Go string cannot realistically reach the
	// uint32 frame limit, so treat an over-length label as an impossible
	// state rather than truncating it.
	if err := t.AppendMessage([]byte(domainSeparatorLabel), []byte(appLabel)); err != nil {
		panic(err)
	}
	return t
}

// frameLabel encodes the Merlin v1 meta-AD frame label || LE32(length).
// It always allocates a fresh backing array and copies label into it, so
// the caller's label slice — including any spare capacity adjacent to its
// elements — is never modified. A length outside the uint32 frame is
// rejected with tooLong instead of being silently truncated.
func frameLabel(label []byte, length int, tooLong error) ([]byte, error) {
	if length < 0 || length > maxFrameLength {
		return nil, tooLong
	}

	framed := make([]byte, len(label)+4)
	copy(framed, label)
	binary.LittleEndian.PutUint32(framed[len(label):], uint32(length))
	return framed, nil
}

// AppendMessage adds message to the transcript under label.
// It returns ErrMessageTooLong when len(message) cannot be represented in
// the Merlin v1 length frame. Neither label nor message is ever modified.
func (t *Transcript) AppendMessage(label, message []byte) error {
	// AD[label || le32(len(message))](message)

	// The StrobeGo API does not support continuation operations,
	// so we have to pass the label and length as a single buffer.
	// Otherwise it will record two meta-AD operations instead of one.
	labelSize, err := frameLabel(label, len(message), ErrMessageTooLong)
	if err != nil {
		return err
	}
	t.s.AD(true, labelSize)

	t.s.AD(false, message)
	return nil
}

// ExtractBytes returns a buffer filled with the verifier's challenge bytes.
// The label parameter is metadata about the challenge, and is also appended to
// the transcript. See the Transcript Protocols section of the Merlin website
// for details on labels. It returns ErrChallengeTooLong when outLen is
// negative or cannot be represented in the uint32 length frame, and never
// modifies label.
func (t *Transcript) ExtractBytes(label []byte, outLen int) ([]byte, error) {
	labelSize, err := frameLabel(label, outLen, ErrChallengeTooLong)
	if err != nil {
		return nil, err
	}
	t.s.AD(true, labelSize)

	// A PRF call directly to the output buffer (in the style of an append API)
	// would be better, but our underlying STROBE library forces an allocation
	// here.
	return t.s.PRF(outLen), nil
}
