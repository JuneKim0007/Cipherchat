package chatterbox

import (
	"encoding/binary"
	"errors"
)

// Pre-defined lable to be used with any key values to produce a HMAC(key, lable)
// for readability, I used string but and convert to Byte
// Hard-coded but its fine as long as key is hidden

const (
	HANDSHAKE_CHECK_LABEL = "HandshakeValidation"
	ROOT_LABEL            = "WhisperRatchet"
	CHAIN_LABEL           = "WhisperMessageKeys"
	KEY_LABEL             = "WhisperText"
)

type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
}
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData() simply attach "VISIBLE" meta Data regarding the message.
// That includes senderID, recieverID, and other few data to handle async Chat.
func (m *Message) EncodeAdditionalData() []byte {
	// Temporary buffer to be returned
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)
	// Message No.
	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	//Last update on ratchting
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))
	// Sender ID
	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	// Receiver ID
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	//Sender's current DH key
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// Initialization(Chatter)
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// Zerorize if the session ends
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {
	s, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return errors.New("no session to tear down")
	}

	if s.MyDHRatchet != nil {
		s.MyDHRatchet.Zeroize()
		s.MyDHRatchet = nil
	}
	if s.RootChain != nil {
		s.RootChain.Zeroize()
		s.RootChain = nil
	}
	if s.SendChain != nil {
		s.SendChain.Zeroize()
		s.SendChain = nil
	}
	if s.ReceiveChain != nil {
		s.ReceiveChain.Zeroize()
		s.ReceiveChain = nil
	}
	// Clean up Cache since Go won't automatically clean them up during garbage collecting.
	for _, key := range s.CachedReceiveKeys {
		if key != nil {
			key.Zeroize()
		}
	}

	// let system know the memory is no longer in use
	for k := range s.CachedReceiveKeys {
		delete(s.CachedReceiveKeys, k)
	}
	// let system know the memory is no longer in use
	delete(c.Sessions, *partnerIdentity)
	return nil
}
