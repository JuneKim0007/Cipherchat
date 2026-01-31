package main

import (
	"SecureChat/chatterbox"
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	fmt.Println("\n===SECURE CHAT DEMONSTRATION===\n")

	// Create chat participants
	alice := chatterbox.NewChatter()
	bob := chatterbox.NewChatter()
	fmt.Println("Alice and Bob are established")

	fmt.Println("\n=== Init Handshake ===\n")
	aliceEphemeral, err := alice.InitiateHandshake(&bob.Identity.PublicKey)
	if err != nil {
		fmt.Println("Alice handshake initiation failed:", err)
		return
	}
	fmt.Println("Alice initiated handshake")

	bobEphemeral, handshakeKeyBob, err := bob.ReturnHandshake(&alice.Identity.PublicKey, aliceEphemeral)
	if err != nil {
		fmt.Println("Bob handshake return failed:", err)
		return
	}
	fmt.Println("Bob returned handshake")

	handshakeKeyAlice, err := alice.FinalizeHandshake(&bob.Identity.PublicKey, bobEphemeral)
	if err != nil {
		fmt.Println("Alice handshake finalization failed:", err)
		return
	}
	fmt.Println("Alice finalized handshake")

	// Verify handshake keys match
	fmt.Printf("\n=== Handshake verification ===\n")
	fmt.Printf("Bob's key  : %x\n", handshakeKeyBob.Key())
	fmt.Printf("Alice's key: %x\n", handshakeKeyAlice.Key())
	if string(handshakeKeyBob.Key()) == string(handshakeKeyAlice.Key()) {
		fmt.Println("!!!!!Handshake Keys Matched!!!!!")
	} else {
		fmt.Println("??????SHOULD NEVER HAPPEN WTH: HANDSHAKE FAILED?????")
		return
	}

	//One directional, synchronous test case
	fmt.Println("\n ===Test 1: One-direction, order-guaranteed communication Alice --> Bob ===\n")
	aliceMessages := []string{
		"Hello World to you Bob",
		"You know I have been thinking about you lately",
		"Maybe we should get back together :)",
		"Wanna meet tommorrow??",
	}

	var sentMessages []*chatterbox.Message
	for i, plaintext := range aliceMessages {
		msg, err := alice.SendMessage(&bob.Identity.PublicKey, plaintext)
		if err != nil {
			fmt.Printf("Alice failed to send message %d: %v\n", i+1, err)
			continue
		}
		fmt.Printf("[Alice] Message %d sent: \"%s\"\n", i+1, plaintext)
		sentMessages = append(sentMessages, msg)
	}

	fmt.Println("\n[Bob] Receiving messages sequentially")
	for i, msg := range sentMessages {
		decrypted, err := bob.ReceiveMessage(msg)
		if err != nil {
			fmt.Printf("Bob failed to decrypt message %d: %v\n", i+1, err)
			continue
		}
		fmt.Printf("[Bob] Message %d decrypted: \"%s\"\n", i+1, decrypted)
		//for testing on testing
		if decrypted != aliceMessages[i] {
			fmt.Printf("MISMATCH GOT: %s\n but Expected: \"%s\"\n", decrypted, aliceMessages[i])
		}
	}

	fmt.Println("\n=== Test 2: Async Communication ===")

	alice.EndSession(&bob.Identity.PublicKey)
	bob.EndSession(&alice.Identity.PublicKey)

	aliceEphemeral, _ = alice.InitiateHandshake(&bob.Identity.PublicKey)
	bobEphemeral, _, _ = bob.ReturnHandshake(&alice.Identity.PublicKey, aliceEphemeral)
	alice.FinalizeHandshake(&bob.Identity.PublicKey, bobEphemeral)

	testMessages := []string{
		"Message 1",
		"Message 2",
		"Message 3",
		"Message 4",
		"Message 5",
	}

	var messages []*chatterbox.Message
	for i, txt := range testMessages {
		msg, _ := alice.SendMessage(&bob.Identity.PublicKey, txt)
		messages = append(messages, msg)
		fmt.Printf("[Alice] Sent message %d: \"%s\"\n", i+1, txt)
	}

	// Shuffle messages to simulate out-of-order network delivery
	shuffled := make([]*chatterbox.Message, len(messages))
	copy(shuffled, messages)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	fmt.Println("\n[Bob] Receiving Asynchronously:")
	receivedOrder := make([]int, len(shuffled))
	for i, msg := range shuffled {
		receivedOrder[i] = msg.Counter
	}
	fmt.Printf("Order: %v\n", receivedOrder)

	//randomize order
	for _, msg := range shuffled {
		decrypted, err := bob.ReceiveMessage(msg)
		if err != nil {
			fmt.Printf("Bob failed to decrypt message (counter %d): %v\n", msg.Counter, err)
			continue
		}

		fmt.Printf("[Bob] Counter %d decrypted: \"%s\"\n", msg.Counter, decrypted)
	}

	fmt.Println("\n=== Test 3: Bidirectional Communication (Double Ratchet) ===")

	bobMessage := "Hello world to you too Alice..."
	bobMsg, err := bob.SendMessage(&alice.Identity.PublicKey, bobMessage)
	if err != nil {
		fmt.Println("Bob failed to send:", err)
	} else {
		fmt.Printf("[Bob] Sent: \"%s\"\n", bobMessage)
		decrypted, err := alice.ReceiveMessage(bobMsg)
		if err != nil {
			fmt.Printf("Alice failed to decrypt: %v\n", err)
		} else {
			fmt.Printf("[Alice] Decrypted: \"%s\"\n", decrypted)
		}
	}

	//Alices sends again
	aliceReply := "Sooo... whats your answer?"
	aliceMsg, _ := alice.SendMessage(&bob.Identity.PublicKey, aliceReply)
	fmt.Printf("[Alice] Sent: \"%s\"\n", aliceReply)
	decrypted, _ := bob.ReceiveMessage(aliceMsg)
	fmt.Printf("[Bob] Decrypted: \"%s\"\n", decrypted)

	bobReplies := []string{
		"Don't you think its too late to come back?",
		"Sorry but this is not going to work.",
		"I already met somebody new. Sorry. Maybe in next life",
	}
	for _, reply := range bobReplies {
		msg, _ := bob.SendMessage(&alice.Identity.PublicKey, reply)
		fmt.Printf("[Bob] Sent: \"%s\"\n", reply)
		dec, _ := alice.ReceiveMessage(msg)
		fmt.Printf("[Alice] Decrypted: \"%s\"\n", dec)
	}

	// to avoid if somebody coping and sending the same cipher text would get the same encryption
	// in order for Bob to decrypt it, Bob needs to store a cached key temporarily, since ratched.
	fmt.Println("\n=== Test 4: Replay Attack Test ===")
	replayMsg, _ := alice.SendMessage(&bob.Identity.PublicKey, "Bob I really need you PLZ")
	fmt.Println("[Alice] Sent message")

	dec1, _ := bob.ReceiveMessage(replayMsg)
	fmt.Printf("[Bob] First receive: \"%s\"\n", dec1)

	dec2, err := bob.ReceiveMessage(replayMsg)
	if err != nil {
		fmt.Printf("[Bob] Replay attempt detected: %v\n", err)
	} else {
		fmt.Printf("[Bob] Replay decrypted: \"%s\" [cached key used]\n", dec2)
	}

	//SESSION ENDS SHOULD NEVER FAIL.
	fmt.Println("\n=== SESSION ENDS === \n")
	err = alice.EndSession(&bob.Identity.PublicKey)
	if err != nil {
		fmt.Println("Alice faild to zerorize its cached keys", err)
	} else {
		fmt.Println("Alice session ends here")
	}

	err = bob.EndSession(&alice.Identity.PublicKey)
	if err != nil {
		fmt.Println("Bob faild to zerorize its cached keys", err)
	} else {
		fmt.Println("Bob session ends here")
	}

	fmt.Println("\n=== All Tests Complete ===\n")
}
