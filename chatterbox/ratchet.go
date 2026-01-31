package chatterbox

import "errors"

// flow of message changes iff

func (c *Chatter) SendMessage(partnerIdentity *PublicKey, plaintext string) (*Message, error) {
	s, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return nil, errors.New("no open session")
	}

	// ratchet logic: if SendChain is null, there is a need to rotate the DH ratchet
	// CHECK IF the flow of the msg has changed
	if s.SendChain == nil {
		s.MyDHRatchet.Zeroize()
		s.MyDHRatchet = GenerateKeyPair()

		tempRoot := s.RootChain.DeriveKey(ROOT_LABEL)
		symmetricEphemeral := DHCombine(s.PartnerDHRatchet, s.MyDHRatchet.PrivateKey)
		s.RootChain = CombineKeys(tempRoot, symmetricEphemeral)

		tempRoot.Zeroize()
		symmetricEphemeral.Zeroize()

		s.SendChain = s.RootChain.DeriveKey(CHAIN_LABEL)
		s.LastUpdate = s.SendCounter
	}

	msg := &Message{
		Sender:        &c.Identity.PublicKey,
		Receiver:      partnerIdentity,
		NextDHRatchet: &s.MyDHRatchet.PublicKey,
		Counter:       s.SendCounter,
		LastUpdate:    s.LastUpdate,
		IV:            NewIV(),
	}

	msgKey := s.SendChain.DeriveKey(KEY_LABEL)
	tempSend := s.SendChain.DeriveKey(CHAIN_LABEL)

	s.SendChain.Zeroize()
	s.SendChain = tempSend

	EAD := msg.EncodeAdditionalData()
	msg.Ciphertext = msgKey.AuthenticatedEncrypt(plaintext, EAD, msg.IV)

	s.SendCounter++
	msgKey.Zeroize()
	return msg, nil
}

func (c *Chatter) ReceiveMessage(msg *Message) (string, error) {
	s, exists := c.Sessions[*msg.Sender]
	if !exists {
		return "", errors.New("no open session")
	}

	// Check if the flow of the message has changed
	// A different logic compare to sendMessage(...), since using receiveChain != nil
	// would not properly handle async operations.
	if msg.NextDHRatchet != nil &&
		(s.PartnerDHRatchet == nil ||
			s.PartnerDHRatchet.X.Cmp(msg.NextDHRatchet.X) != 0 ||
			s.PartnerDHRatchet.Y.Cmp(msg.NextDHRatchet.Y) != 0) {

		tempRoot := s.RootChain.DeriveKey(ROOT_LABEL)
		tempSym := DHCombine(msg.NextDHRatchet, s.MyDHRatchet.PrivateKey)
		s.RootChain = CombineKeys(tempRoot, tempSym)

		//Clean up old keys since its used.
		if s.ReceiveChain != nil {
			s.ReceiveChain.Zeroize()
		}
		s.ReceiveChain = s.RootChain.DeriveKey(CHAIN_LABEL)
		s.ReceiveCounter = msg.LastUpdate
		s.PartnerDHRatchet = msg.NextDHRatchet

		for k, v := range s.CachedReceiveKeys {
			if v != nil {
				v.Zeroize()
			}
			delete(s.CachedReceiveKeys, k)
		}

		if s.SendChain != nil {
			s.SendChain.Zeroize()
			s.SendChain = nil
		}

		tempRoot.Zeroize()
		tempSym.Zeroize()
	}

	//check if the entity recieved the cipher text has alread cached the key
	// by looking up the counter value in the attached tag.
	// You may want to avoid attaching too much info onto a tag.
	if cachedKey, exists := s.CachedReceiveKeys[msg.Counter]; exists {
		msgKey := cachedKey.DeriveKey(KEY_LABEL)
		EAD := msg.EncodeAdditionalData()
		plaintext, err := msgKey.AuthenticatedDecrypt(msg.Ciphertext, EAD, msg.IV)
		msgKey.Zeroize()
		return plaintext, err
	}

	for i := s.ReceiveCounter; i <= msg.Counter; i++ {
		// Copy the current chain state before caching
		s.CachedReceiveKeys[i] = s.ReceiveChain.Clone()
		// Proceed to next chain state
		nextChain := s.ReceiveChain.DeriveKey(CHAIN_LABEL)
		s.ReceiveChain.Zeroize()
		s.ReceiveChain = nextChain
	}
	s.ReceiveCounter = msg.Counter + 1

	//Decrypt if async chat using cached key
	keyChain := s.CachedReceiveKeys[msg.Counter]
	msgKey := keyChain.DeriveKey(KEY_LABEL)
	EAD := msg.EncodeAdditionalData()
	plaintext, err := msgKey.AuthenticatedDecrypt(msg.Ciphertext, EAD, msg.IV)
	if err != nil {
		msgKey.Zeroize()
		return "", err
	}

	msgKey.Zeroize()

	return plaintext, nil
}
