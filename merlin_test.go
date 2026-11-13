package merlin

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// Initialize STROBE-128(4d65726c696e2076312e30)   # b"Merlin v1.0"
// meta-AD : 646f6d2d736570 || LE32(13)    # b"dom-sep"
// AD : 746573742070726f746f636f6c    # b"test protocol"
// meta-AD : 736f6d65206c6162656c || LE32(9)       # b"some label"
// AD : 736f6d652064617461    # b"some data"
// meta-AD : 6368616c6c656e6765 || LE32(32)        # b"challenge"
// PRF: d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615
// test transcript::tests::equivalence_simple ... ok

func TestSimpleTranscript(t *testing.T) {
	mt := NewTranscript("test protocol")
	if err := mt.AppendMessage([]byte("some label"), []byte("some data")); err != nil {
		t.Fatalf("AppendMessage failed: %v", err)
	}

	cBytes, err := mt.ExtractBytes([]byte("challenge"), 32)
	if err != nil {
		t.Fatalf("ExtractBytes failed: %v", err)
	}
	cHex := fmt.Sprintf("%x", cBytes)
	expectedHex := "d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615"

	if cHex != expectedHex {
		t.Errorf("\nGot : %s\nWant: %s", cHex, expectedHex)
	}
}

func TestComplexTranscript(t *testing.T) {
	tr := NewTranscript("test protocol")
	if err := tr.AppendMessage([]byte("step1"), []byte("some data")); err != nil {
		t.Fatalf("AppendMessage failed: %v", err)
	}

	data := make([]byte, 1024)
	for i := range data {
		data[i] = 99
	}

	var chlBytes []byte
	for i := 0; i < 32; i++ {
		var err error
		chlBytes, err = tr.ExtractBytes([]byte("challenge"), 32)
		if err != nil {
			t.Fatalf("ExtractBytes failed: %v", err)
		}
		if err = tr.AppendMessage([]byte("bigdata"), data); err != nil {
			t.Fatalf("AppendMessage failed: %v", err)
		}
		if err = tr.AppendMessage([]byte("challengedata"), chlBytes); err != nil {
			t.Fatalf("AppendMessage failed: %v", err)
		}
	}

	expectedChlHex := "a8c933f54fae76e3f9bea93648c1308e7dfa2152dd51674ff3ca438351cf003c"
	chlHex := fmt.Sprintf("%x", chlBytes)

	if chlHex != expectedChlHex {
		t.Errorf("\nGot : %s\nWant: %s", chlHex, expectedChlHex)
	}
}

// Inputs with spare capacity must not be overwritten when the length frame
// is appended. This guards against reintroducing append(label, frame...),
// which would mutate memory adjacent to the caller's slice.
func TestDoesNotMutateInputs(t *testing.T) {
	label := make([]byte, len("label"), len("label")+8)
	copy(label, "label")
	labelCap := label[:cap(label)]
	for i := len(label); i < len(labelCap); i++ {
		labelCap[i] = 0xAA
	}
	label = label[:len("label")]
	labelSnapshot := append([]byte(nil), label...)

	message := make([]byte, len("message"), len("message")+8)
	copy(message, "message")
	messageCap := message[:cap(message)]
	for i := len(message); i < len(messageCap); i++ {
		messageCap[i] = 0xBB
	}
	message = message[:len("message")]
	messageSnapshot := append([]byte(nil), message...)

	tr := NewTranscript("test protocol")
	if err := tr.AppendMessage(label, message); err != nil {
		t.Fatalf("AppendMessage failed: %v", err)
	}
	if _, err := tr.ExtractBytes(label, 32); err != nil {
		t.Fatalf("ExtractBytes failed: %v", err)
	}

	if !bytes.Equal(label, labelSnapshot) {
		t.Errorf("label mutated: got %v, want %v", label, labelSnapshot)
	}
	if !bytes.Equal(message, messageSnapshot) {
		t.Errorf("message mutated: got %v, want %v", message, messageSnapshot)
	}

	// The spare capacity after each input must be untouched as well.
	for _, b := range label[len(label):cap(label)] {
		if b != 0xAA {
			t.Fatalf("memory adjacent to label was overwritten: %v", label[:cap(label)])
		}
	}
	for _, b := range message[len(message):cap(message)] {
		if b != 0xBB {
			t.Fatalf("memory adjacent to message was overwritten: %v", message[:cap(message)])
		}
	}
}

// Lengths outside the Merlin v1 uint32 frame must be reported rather than
// truncated, since truncation would make distinct lengths collide.
func TestOversizedFramesRejected(t *testing.T) {
	tr := NewTranscript("test protocol")

	if _, err := tr.ExtractBytes([]byte("challenge"), maxFrameLength+1); !errors.Is(err, ErrChallengeTooLong) {
		t.Errorf("outLen = 2^32: got %v, want ErrChallengeTooLong", err)
	}
	if _, err := tr.ExtractBytes([]byte("challenge"), -1); !errors.Is(err, ErrChallengeTooLong) {
		t.Errorf("negative outLen: got %v, want ErrChallengeTooLong", err)
	}

	if _, err := frameLabel(nil, maxFrameLength+1, ErrMessageTooLong); !errors.Is(err, ErrMessageTooLong) {
		t.Errorf("length = 2^32: got %v, want ErrMessageTooLong", err)
	}
	if _, err := frameLabel(nil, -1, ErrMessageTooLong); !errors.Is(err, ErrMessageTooLong) {
		t.Errorf("negative length: got %v, want ErrMessageTooLong", err)
	}

	// A rejected frame must leave the transcript state untouched.
	before, err := tr.ExtractBytes([]byte("challenge"), 32)
	if err != nil {
		t.Fatalf("ExtractBytes failed: %v", err)
	}
	fresh := NewTranscript("test protocol")
	after, err := fresh.ExtractBytes([]byte("challenge"), 32)
	if err != nil {
		t.Fatalf("ExtractBytes failed: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("rejected frame operation changed the transcript state")
	}
}

// The frame encoding for in-range lengths must stay byte-identical to the
// Merlin v1 label || LE32(length) wire format.
func TestFrameEncoding(t *testing.T) {
	framed, err := frameLabel([]byte("some label"), 9, ErrMessageTooLong)
	if err != nil {
		t.Fatalf("frameLabel failed: %v", err)
	}

	expected := append([]byte("some label"), 0x09, 0x00, 0x00, 0x00)
	if !bytes.Equal(framed, expected) {
		t.Errorf("got %v, want %v", framed, expected)
	}

	// Framing must allocate a fresh, tightly sized array rather than reuse
	// any spare capacity of the caller's label.
	if cap(framed) != len(framed) {
		t.Errorf("frame has spare capacity %d, want %d", cap(framed), len(framed))
	}
}

// Separate transcripts own independent STROBE state; running the same
// protocol concurrently from many goroutines must give the deterministic
// Merlin result without cross-talk.
func TestConcurrentIndependentTranscripts(t *testing.T) {
	const goroutines = 64

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()

			tr := NewTranscript("test protocol")
			if err := tr.AppendMessage([]byte("some label"), []byte("some data")); err != nil {
				errs <- err
				return
			}
			challenge, err := tr.ExtractBytes([]byte("challenge"), 32)
			if err != nil {
				errs <- err
				return
			}

			want := "d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615"
			if got := fmt.Sprintf("%x", challenge); got != want {
				errs <- fmt.Errorf("got %s, want %s", got, want)
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
