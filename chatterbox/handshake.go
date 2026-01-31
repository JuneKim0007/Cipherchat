package chatterbox

// HAND SHAKE SECTION
// Alice and BOB both generate a key pair
// They both share their public Key.
// Using Diffie Helman, they derive the same root key
// to correctly identify whether they shared keys successfully
// we have to check if their Alice.combinedKey == Bob.combinedKey

// Since this is just for demonstrating purpose
//  Alice and Bob may need to generate their keys in many cases on their local machine separately

import (
	"errors"
)

func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {
	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("session already open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       GenerateKeyPair(),
		SendCounter:       1,
		LastUpdate:        1,
		ReceiveCounter:    0,
	}

	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, nil
}

func (c *Chatter) ReturnHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {
	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("session already open")
	}

	s := &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       GenerateKeyPair(),
		PartnerDHRatchet:  partnerEphemeral,
		SendCounter:       1,
		LastUpdate:        1,
		ReceiveCounter:    1,
	}
	c.Sessions[*partnerIdentity] = s

	K1 := DHCombine(partnerIdentity, s.MyDHRatchet.PrivateKey)
	K2 := DHCombine(partnerEphemeral, c.Identity.PrivateKey)
	K3 := DHCombine(partnerEphemeral, s.MyDHRatchet.PrivateKey)

	s.RootChain = CombineKeys(K1, K2, K3)
	s.ReceiveChain = s.RootChain.DeriveKey(CHAIN_LABEL)

	// zeroize temp keys
	K1.Zeroize()
	K2.Zeroize()
	K3.Zeroize()

	combinedKey := s.RootChain.DeriveKey(HANDSHAKE_CHECK_LABEL)
	return &s.MyDHRatchet.PublicKey, combinedKey, nil
}

// FinalizeHandshake for Alice (initiator)
func (c *Chatter) FinalizeHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*SymmetricKey, error) {
	s, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return nil, errors.New("session not open")
	}

	s.ReceiveCounter = 1
	s.PartnerDHRatchet = partnerEphemeral

	K1 := DHCombine(partnerEphemeral, c.Identity.PrivateKey)
	K2 := DHCombine(partnerIdentity, s.MyDHRatchet.PrivateKey)
	K3 := DHCombine(partnerEphemeral, s.MyDHRatchet.PrivateKey)

	s.RootChain = CombineKeys(K1, K2, K3)
	s.SendChain = s.RootChain.DeriveKey(CHAIN_LABEL)

	K1.Zeroize()
	K2.Zeroize()
	K3.Zeroize()

	combinedKey := s.RootChain.DeriveKey(HANDSHAKE_CHECK_LABEL)
	return combinedKey, nil
}
