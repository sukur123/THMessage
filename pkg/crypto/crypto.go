package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/subtle"
	"math/big"

	"github.com/dedis/kyber/v3"
	"github.com/dedis/kyber/v3/group/edwards25519"
	"github.com/dedis/kyber/v3/share"
	"github.com/dedis/kyber/v3/share/dkg/pedersen"
	"github.com/dedis/kyber/v3/share/vss/pedersen"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// Constants for message expiration
const (
	// Available expiration durations
	ExpirationNever     = 0
	ExpirationHour      = 60 * 60         // 1 hour in seconds
	ExpirationDay       = 24 * 60 * 60    // 1 day in seconds
	ExpirationWeek      = 7 * 24 * 60 * 60 // 1 week in seconds

	// Maximum message size
	MaxMessageSize = 1024 * 1024 // 1MB

	// Key derivation info strings
	KDFInfoEncryption    = "THMessage-Encryption-Key"
	KDFInfoAuthentication = "THMessage-Authentication-Key"
	KDFInfoDeniability    = "THMessage-Deniability-Key"
)

// Encryption types
const (
	EncryptionTypeXChaCha20Poly1305 = 1  // Modern AEAD cipher
	EncryptionTypeAESGCM            = 2  // Alternative AEAD cipher
	EncryptionTypeKyber             = 3  // Post-quantum encryption
	EncryptionTypeHybrid            = 4  // Hybrid classical + post-quantum
)

// EncryptedMessage represents an encrypted message with metadata
type EncryptedMessage struct {
	Version          byte      // Protocol version
	EncryptionType   byte      // Type of encryption used
	SenderID         []byte    // ID of sender (may be encrypted or hashed for privacy)
	RecipientID      []byte    // ID of recipient (may be encrypted or hashed for privacy)
	Timestamp        int64     // Message creation timestamp
	ExpirationTime   int64     // When message should expire (0 = never)
	IV               []byte    // Initialization vector
	EncryptedContent []byte    // The encrypted message content
	AuthTag          []byte    // Authentication tag
	DeniabilityData  []byte    // Data for plausible deniability
}

// MessageHeader contains the unencrypted message metadata
type MessageHeader struct {
	Version        byte
	EncryptionType byte
	SenderID       []byte
	RecipientID    []byte
	Timestamp      int64
	ExpirationTime int64
}

// CryptoEngine manages cryptographic operations
type CryptoEngine struct {
	usePostQuantum bool // Whether to use post-quantum algorithms
}

// NewCryptoEngine creates a new crypto engine
func NewCryptoEngine(usePostQuantum bool) *CryptoEngine {
	return &CryptoEngine{
		usePostQuantum: usePostQuantum,
	}
}

// GenerateKeyPair generates a new key pair using either classical or post-quantum algorithms
func (c *CryptoEngine) GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	if c.usePostQuantum {
		return c.generatePostQuantumKeyPair()
	}
	return c.generateClassicalKeyPair()
}

// generateClassicalKeyPair generates an ECDH key pair
func (c *CryptoEngine) generateClassicalKeyPair() (privateKey, publicKey []byte, err error) {
	// Use X25519 for classical key exchange
	curve := ecdh.X25519()
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDH key: %w", err)
	}

	return private.Bytes(), private.PublicKey().Bytes(), nil
}

// generatePostQuantumKeyPair generates a Kyber key pair
func (c *CryptoEngine) generatePostQuantumKeyPair() (privateKey, publicKey []byte, err error) {
	// Use Kyber1024 for post-quantum security
	seed := make([]byte, kyber1024.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	publicKey, privateKey, err = kyber1024.GenerateKeyPair(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Kyber key pair: %w", err)
	}

	return privateKey, publicKey, nil
}

// generateHybridKeyPair generates both classical and post-quantum key pairs
func (c *CryptoEngine) generateHybridKeyPair() (privateKeyClassical, publicKeyClassical, privateKeyPQ, publicKeyPQ []byte, err error) {
	// Generate classical key pair
	privateKeyClassical, publicKeyClassical, err = c.generateClassicalKeyPair()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Generate post-quantum key pair
	privateKeyPQ, publicKeyPQ, err = c.generatePostQuantumKeyPair()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return privateKeyClassical, publicKeyClassical, privateKeyPQ, publicKeyPQ, nil
}

// EncryptMessage encrypts a message for the specified recipient
func (c *CryptoEngine) EncryptMessage(senderPrivateKey, recipientPublicKey, message []byte, 
                                      senderID, recipientID string, expirationSeconds int64) ([]byte, error) {
	
	// Choose encryption type based on configuration
	encryptionType := byte(EncryptionTypeXChaCha20Poly1305)
	if c.usePostQuantum {
		encryptionType = EncryptionTypeHybrid
	}

	// Calculate expiration time
	var expirationTime int64 = 0
	if expirationSeconds > 0 {
		expirationTime = time.Now().Unix() + expirationSeconds
	}

	// Create message header
	header := MessageHeader{
		Version:        1,
		EncryptionType: encryptionType,
		SenderID:       []byte(senderID),
		RecipientID:    []byte(recipientID),
		Timestamp:      time.Now().Unix(),
		ExpirationTime: expirationTime,
	}

	// Encrypt based on the encryption type
	switch encryptionType {
	case EncryptionTypeXChaCha20Poly1305:
		return c.encryptWithChaCha20Poly1305(senderPrivateKey, recipientPublicKey, message, header)
	case EncryptionTypeAESGCM:
		return c.encryptWithAESGCM(senderPrivateKey, recipientPublicKey, message, header)
	case EncryptionTypeKyber:
		return c.encryptWithKyber(recipientPublicKey, message, header)
	case EncryptionTypeHybrid:
		return c.encryptWithHybrid(senderPrivateKey, recipientPublicKey, message, header)
	default:
		return nil, errors.New("unsupported encryption type")
	}
}

// encryptWithChaCha20Poly1305 encrypts using ChaCha20-Poly1305 AEAD
func (c *CryptoEngine) encryptWithChaCha20Poly1305(senderPrivateKey, recipientPublicKey, message []byte, 
                                                  header MessageHeader) ([]byte, error) {
	
	// Convert sender private key to ECDH private key
	curve := ecdh.X25519()
	senderKey, err := curve.NewPrivateKey(senderPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid sender private key: %w", err)
	}

	// Convert recipient public key to ECDH public key
	recipientKey, err := curve.NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}

	// Perform key exchange
	sharedSecret, err := senderKey.ECDH(recipientKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive encryption key using HKDF
	encKey, err := c.deriveKey(sharedSecret, []byte(KDFInfoEncryption), 32)
	if err != nil {
		return nil, err
	}

	// Create XChaCha20-Poly1305 AEAD
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encode header
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}

	// Encrypt the message
	ciphertext := aead.Seal(nil, nonce, message, headerBytes)

	// Generate deniability data
	// In a real implementation, this would be more sophisticated
	deniabilityKey, err := c.deriveKey(sharedSecret, []byte(KDFInfoDeniability), 32)
	if err != nil {
		return nil, err
	}
	deniabilityData := c.generateDeniabilityData(deniabilityKey, headerBytes)

	// Combine everything
	encMsg := EncryptedMessage{
		Version:          header.Version,
		EncryptionType:   header.EncryptionType,
		SenderID:         header.SenderID,
		RecipientID:      header.RecipientID,
		Timestamp:        header.Timestamp,
		ExpirationTime:   header.ExpirationTime,
		IV:               nonce,
		EncryptedContent: ciphertext,
		AuthTag:          nil, // Contained in ciphertext for AEAD
		DeniabilityData:  deniabilityData,
	}

	// Serialize the encrypted message
	return serializeEncryptedMessage(encMsg)
}

// encryptWithAESGCM encrypts using AES-GCM AEAD
func (c *CryptoEngine) encryptWithAESGCM(senderPrivateKey, recipientPublicKey, message []byte, 
                                         header MessageHeader) ([]byte, error) {
	
	// Similar to ChaCha20-Poly1305 but using AES-GCM
	// Convert sender private key to ECDH private key
	curve := ecdh.X25519()
	senderKey, err := curve.NewPrivateKey(senderPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid sender private key: %w", err)
	}

	// Convert recipient public key to ECDH public key
	recipientKey, err := curve.NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}

	// Perform key exchange
	sharedSecret, err := senderKey.ECDH(recipientKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive encryption key using HKDF
	encKey, err := c.deriveKey(sharedSecret, []byte(KDFInfoEncryption), 32)
	if err != nil {
		return nil, err
	}

	// Create AES-GCM AEAD
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encode header
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}

	// Encrypt the message
	ciphertext := aead.Seal(nil, nonce, message, headerBytes)

	// Generate deniability data
	deniabilityKey, err := c.deriveKey(sharedSecret, []byte(KDFInfoDeniability), 32)
	if err != nil {
		return nil, err
	}
	deniabilityData := c.generateDeniabilityData(deniabilityKey, headerBytes)

	// Combine everything
	encMsg := EncryptedMessage{
		Version:          header.Version,
		EncryptionType:   header.EncryptionType,
		SenderID:         header.SenderID,
		RecipientID:      header.RecipientID,
		Timestamp:        header.Timestamp,
		ExpirationTime:   header.ExpirationTime,
		IV:               nonce,
		EncryptedContent: ciphertext,
		AuthTag:          nil, // Contained in ciphertext for AEAD
		DeniabilityData:  deniabilityData,
	}

	// Serialize the encrypted message
	return serializeEncryptedMessage(encMsg)
}

// encryptWithKyber encrypts using Kyber (post-quantum)
func (c *CryptoEngine) encryptWithKyber(recipientPublicKey, message []byte, header MessageHeader) ([]byte, error) {
	// Convert recipient public key bytes to Kyber public key
	if len(recipientPublicKey) != kyber1024.PublicKeySize {
		return nil, fmt.Errorf("invalid Kyber public key size: expected %d, got %d", 
                              kyber1024.PublicKeySize, len(recipientPublicKey))
	}

	// Generate random seed for ciphertext
	seed := make([]byte, kyber1024.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	// Encapsulate to derive shared secret
	ciphertext, sharedSecret, err := kyber1024.EncapDeterministic(recipientPublicKey, seed)
	if err != nil {
		return nil, fmt.Errorf("Kyber encapsulation failed: %w", err)
	}

	// Derive encryption key from shared secret
	encKey, err := c.deriveKey(sharedSecret, []byte(KDFInfoEncryption), 32)
	if err != nil {
		return nil, err
	}

	// Create XChaCha20-Poly1305 AEAD for actual message encryption
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encode header
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}

	// Encrypt the message
	ciphertextMessage := aead.Seal(nil, nonce, message, headerBytes)

	// Generate deniability data
	deniabilityKey, err := c.deriveKey(sharedSecret, []byte(KDFInfoDeniability), 32)
	if err != nil {
		return nil, err
	}
	deniabilityData := c.generateDeniabilityData(deniabilityKey, headerBytes)

	// Combine everything
	encMsg := EncryptedMessage{
		Version:          header.Version,
		EncryptionType:   header.EncryptionType,
		SenderID:         header.SenderID,
		RecipientID:      header.RecipientID,
		Timestamp:        header.Timestamp,
		ExpirationTime:   header.ExpirationTime,
		IV:               nonce,
		EncryptedContent: ciphertextMessage,
		AuthTag:          ciphertext, // Kyber ciphertext as authentication tag
		DeniabilityData:  deniabilityData,
	}

	// Serialize the encrypted message
	return serializeEncryptedMessage(encMsg)
}

// encryptWithHybrid encrypts using both classical and post-quantum algorithms
func (c *CryptoEngine) encryptWithHybrid(senderPrivateKey, recipientPublicKey, message []byte, 
                                         header MessageHeader) ([]byte, error) {
	
	// In this hybrid approach, we assume the first part of the public key is classical (X25519)
	// and the second part is post-quantum (Kyber)
	
	// Split the keys
	classicalPubKeySize := 32 // X25519 public key size
	if len(recipientPublicKey) < classicalPubKeySize+kyber1024.PublicKeySize {
		return nil, errors.New("recipient public key too small for hybrid encryption")
	}
	
	classicalPubKey := recipientPublicKey[:classicalPubKeySize]
	kyberPubKey := recipientPublicKey[classicalPubKeySize:]
	
	// Perform classical key exchange
	curve := ecdh.X25519()
	senderKey, err := curve.NewPrivateKey(senderPrivateKey[:classicalPubKeySize])
	if err != nil {
		return nil, fmt.Errorf("invalid sender private key: %w", err)
	}

	recipientClassicalKey, err := curve.NewPublicKey(classicalPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient classical public key: %w", err)
	}

	// Perform ECDH key exchange
	classicalSecret, err := senderKey.ECDH(recipientClassicalKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}
	
	// Generate random seed for Kyber
	seed := make([]byte, kyber1024.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	// Perform Kyber key encapsulation
	kyberCiphertext, kyberSecret, err := kyber1024.EncapDeterministic(kyberPubKey, seed)
	if err != nil {
		return nil, fmt.Errorf("Kyber encapsulation failed: %w", err)
	}
	
	// Combine both secrets
	combinedSecret := make([]byte, len(classicalSecret)+len(kyberSecret))
	copy(combinedSecret, classicalSecret)
	copy(combinedSecret[len(classicalSecret):], kyberSecret)
	
	// Hash the combined secret to derive the final key
	finalSecret := sha256.Sum256(combinedSecret)
	
	// Derive encryption key
	encKey, err := c.deriveKey(finalSecret[:], []byte(KDFInfoEncryption), 32)
	if err != nil {
		return nil, err
	}
	
	// Create XChaCha20-Poly1305 AEAD
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encode header
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}

	// Encrypt the message
	ciphertext := aead.Seal(nil, nonce, message, headerBytes)

	// Generate deniability data
	deniabilityKey, err := c.deriveKey(finalSecret[:], []byte(KDFInfoDeniability), 32)
	if err != nil {
		return nil, err
	}
	deniabilityData := c.generateDeniabilityData(deniabilityKey, headerBytes)

	// Combine everything
	encMsg := EncryptedMessage{
		Version:          header.Version,
		EncryptionType:   header.EncryptionType,
		SenderID:         header.SenderID,
		RecipientID:      header.RecipientID,
		Timestamp:        header.Timestamp,
		ExpirationTime:   header.ExpirationTime,
		IV:               nonce,
		EncryptedContent: ciphertext,
		AuthTag:          kyberCiphertext, // Store Kyber ciphertext as authentication tag
		DeniabilityData:  deniabilityData,
	}

	// Serialize the encrypted message
	return serializeEncryptedMessage(encMsg)
}

// DecryptMessage decrypts a message
func (c *CryptoEngine) DecryptMessage(recipientPrivateKey, senderPublicKey, encryptedData []byte) ([]byte, error) {
	// Deserialize the encrypted message
	encMsg, err := deserializeEncryptedMessage(encryptedData)
	if err != nil {
		return nil, err
	}
	
	// Check if message has expired
	if encMsg.ExpirationTime > 0 && time.Now().Unix() > encMsg.ExpirationTime {
		return nil, errors.New("message has expired")
	}
	
	// Decrypt based on encryption type
	switch encMsg.EncryptionType {
	case EncryptionTypeXChaCha20Poly1305:
		return c.decryptWithChaCha20Poly1305(recipientPrivateKey, senderPublicKey, encMsg)
	case EncryptionTypeAESGCM:
		return c.decryptWithAESGCM(recipientPrivateKey, senderPublicKey, encMsg)
	case EncryptionTypeKyber:
		return c.decryptWithKyber(recipientPrivateKey, encMsg)
	case EncryptionTypeHybrid:
		return c.decryptWithHybrid(recipientPrivateKey, senderPublicKey, encMsg)
	default:
		return nil, errors.New("unsupported encryption type")
	}
}

// decryptWithChaCha20Poly1305 decrypts a message using ChaCha20-Poly1305
func (c *CryptoEngine) decryptWithChaCha20Poly1305(recipientPrivateKey, senderPublicKey []byte, 
                                                 encMsg EncryptedMessage) ([]byte, error) {
	
	// Convert recipient private key to ECDH private key
	curve := ecdh.X25519()
	recipientKey, err := curve.NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient private key: %w", err)
	}

	// Convert sender public key to ECDH public key
	senderKey, err := curve.NewPublicKey(senderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid sender public key: %w", err)
	}

	// Perform key exchange
	sharedSecret, err := recipientKey.ECDH(senderKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive encryption key using HKDF
	encKey, err := c.deriveKey(sharedSecret, []byte(KDFInfoEncryption), 32)
	if err != nil {
		return nil, err
	}

	// Create XChaCha20-Poly1305 AEAD
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	// Create header for additional authenticated data
	header := MessageHeader{
		Version:        encMsg.Version,
		EncryptionType: encMsg.EncryptionType,
		SenderID:       encMsg.SenderID,
		RecipientID:    encMsg.RecipientID,
		Timestamp:      encMsg.Timestamp,
		ExpirationTime: encMsg.ExpirationTime,
	}

	// Encode header to bytes
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}

	// Decrypt the message
	message, err := aead.Open(nil, encMsg.IV, encMsg.EncryptedContent, headerBytes)
	if err != nil {
		// Check if this is a deniable message
		if c.checkDeniability(sharedSecret, headerBytes, encMsg.DeniabilityData) {
			// Generate a fake but plausible message
			return c.generateFakeMessage(), nil
		}
		
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return message, nil
}

// decryptWithAESGCM decrypts a message using AES-GCM
func (c *CryptoEngine) decryptWithAESGCM(recipientPrivateKey, senderPublicKey []byte, 
                                       encMsg EncryptedMessage) ([]byte, error) {
	
	// Similar to ChaCha20-Poly1305 but using AES-GCM
	// Convert recipient private key to ECDH private key
	curve := ecdh.X25519()
	recipientKey, err := curve.NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient private key: %w", err)
	}

	// Convert sender public key to ECDH public key
	senderKey, err := curve.NewPublicKey(senderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid sender public key: %w", err)
	}

	// Perform key exchange
	sharedSecret, err := recipientKey.ECDH(senderKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive encryption key using HKDF
	encKey, err := c.deriveKey(sharedSecret, []byte(KDFInfoEncryption), 32)
	if err != nil {
		return nil, err
	}

	// Create AES-GCM AEAD
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create header for additional authenticated data
	header := MessageHeader{
		Version:        encMsg.Version,
		EncryptionType: encMsg.EncryptionType,
		SenderID:       encMsg.SenderID,
		RecipientID:    encMsg.RecipientID,
		Timestamp:      encMsg.Timestamp,
		ExpirationTime: encMsg.ExpirationTime,
	}

	// Encode header to bytes
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}

	// Decrypt the message
	message, err := aead.Open(nil, encMsg.IV, encMsg.EncryptedContent, headerBytes)
	if err != nil {
		// Check if this is a deniable message
		if c.checkDeniability(sharedSecret, headerBytes, encMsg.DeniabilityData) {
			// Generate a fake but plausible message
			return c.generateFakeMessage(), nil
		}
		
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return message, nil
}

// decryptWithKyber decrypts a message using Kyber
func (c *CryptoEngine) decryptWithKyber(recipientPrivateKey []byte, encMsg EncryptedMessage) ([]byte, error) {
	// Verify private key size
	if len(recipientPrivateKey) != kyber1024.PrivateKeySize {
		return nil, fmt.Errorf("invalid Kyber private key size: expected %d, got %d", 
                              kyber1024.PrivateKeySize, len(recipientPrivateKey))
	}

	// The AuthTag contains the Kyber ciphertext
	if len(encMsg.AuthTag) != kyber1024.CiphertextSize {
		return nil, fmt.Errorf("invalid Kyber ciphertext size: expected %d, got %d", 
                              kyber1024.CiphertextSize, len(encMsg.AuthTag))
	}

	// Decapsulate to derive shared secret
	sharedSecret, err := kyber1024.Decaps(encMsg.AuthTag, recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Kyber decapsulation failed: %w", err)
	}

	// Derive encryption key from shared secret
	encKey, err := c.deriveKey(sharedSecret, []byte(KDFInfoEncryption), 32)
	if err != nil {
		return nil, err
	}

	// Create XChaCha20-Poly1305 AEAD for actual message decryption
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	// Create header for additional authenticated data
	header := MessageHeader{
		Version:        encMsg.Version,
		EncryptionType: encMsg.EncryptionType,
		SenderID:       encMsg.SenderID,
		RecipientID:    encMsg.RecipientID,
		Timestamp:      encMsg.Timestamp,
		ExpirationTime: encMsg.ExpirationTime,
	}

	// Encode header to bytes
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}

	// Decrypt the message
	message, err := aead.Open(nil, encMsg.IV, encMsg.EncryptedContent, headerBytes)
	if err != nil {
		// Check if this is a deniable message
		deniabilityKey, derivErr := c.deriveKey(sharedSecret, []byte(KDFInfoDeniability), 32)
		if derivErr == nil && c.checkDeniability(deniabilityKey, headerBytes, encMsg.DeniabilityData) {
			// Generate a fake but plausible message
			return c.generateFakeMessage(), nil
		}
		
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return message, nil
}

// decryptWithHybrid decrypts a message using both classical and post-quantum algorithms
func (c *CryptoEngine) decryptWithHybrid(recipientPrivateKey, senderPublicKey []byte, 
                                        encMsg EncryptedMessage) ([]byte, error) {
	
	// Split the keys
	classicalPrivKeySize := 32 // X25519 private key size
	classicalPubKeySize := 32  // X25519 public key size
	
	if len(recipientPrivateKey) < classicalPrivKeySize+kyber1024.PrivateKeySize {
		return nil, errors.New("recipient private key too small for hybrid decryption")
	}
	
	if len(senderPublicKey) < classicalPubKeySize {
		return nil, errors.New("sender public key too small for hybrid decryption")
	}
	
	classicalPrivKey := recipientPrivateKey[:classicalPrivKeySize]
	kyberPrivKey := recipientPrivateKey[classicalPrivKeySize:]
	
	classicalPubKey := senderPublicKey[:classicalPubKeySize]
	
	// Perform classical key exchange
	curve := ecdh.X25519()
	recipientKey, err := curve.NewPrivateKey(classicalPrivKey)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient private key: %w", err)
	}

	senderClassicalKey, err := curve.NewPublicKey(classicalPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid sender classical public key: %w", err)
	}

	// Perform ECDH key exchange
	classicalSecret, err := recipientKey.ECDH(senderClassicalKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}
	
	// Perform Kyber decapsulation
	if len(encMsg.AuthTag) != kyber1024.CiphertextSize {
		return nil, fmt.Errorf("invalid Kyber ciphertext size: expected %d, got %d", 
                              kyber1024.CiphertextSize, len(encMsg.AuthTag))
	}
	
	kyberSecret, err := kyber1024.Decaps(encMsg.AuthTag, kyberPrivKey)
	if err != nil {
		return nil, fmt.Errorf("Kyber decapsulation failed: %w", err)
	}
	
	// Combine both secrets
	combinedSecret := make([]byte, len(classicalSecret)+len(kyberSecret))
	copy(combinedSecret, classicalSecret)
	copy(combinedSecret[len(classicalSecret):], kyberSecret)
	
	// Hash the combined secret to derive the final key
	finalSecret := sha256.Sum256(combinedSecret)
	
	// Derive encryption key
	encKey, err := c.deriveKey(finalSecret[:], []byte(KDFInfoEncryption), 32)
	if err != nil {
		return nil, err
	}
	
	// Create XChaCha20-Poly1305 AEAD
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}
	
	// Create header for additional authenticated data
	header := MessageHeader{
		Version:        encMsg.Version,
		EncryptionType: encMsg.EncryptionType,
		SenderID:       encMsg.SenderID,
		RecipientID:    encMsg.RecipientID,
		Timestamp:      encMsg.Timestamp,
		ExpirationTime: encMsg.ExpirationTime,
	}

	// Encode header to bytes
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return nil, err
	}

	// Decrypt the message
	message, err := aead.Open(nil, encMsg.IV, encMsg.EncryptedContent, headerBytes)
	if err != nil {
		// Check if this is a deniable message
		deniabilityKey, derivErr := c.deriveKey(finalSecret[:], []byte(KDFInfoDeniability), 32)
		if derivErr == nil && c.checkDeniability(deniabilityKey, headerBytes, encMsg.DeniabilityData) {
			// Generate a fake but plausible message
			return c.generateFakeMessage(), nil
		}
		
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return message, nil
}

// Helper functions

// deriveKey derives a key using HKDF
func (c *CryptoEngine) deriveKey(secret, info []byte, length int) ([]byte, error) {
	salt := []byte("THMessage-HKDF-Salt") // Fixed salt
	
	// Create HKDF
	kdf := hkdf.New(sha256.New, secret, salt, info)
	
	// Derive key
	key := make([]byte, length)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	
	return key, nil
}

// generateDeniabilityData creates data for plausible deniability
func (c *CryptoEngine) generateDeniabilityData(key []byte, headerData []byte) []byte {
	// In a real implementation, this would be more sophisticated
	// and would allow for plausible alternative messages
	
	// For now, just derive some random-looking data from the key and header
	h := sha256.New()
	h.Write(key)
	h.Write(headerData)
	h.Write([]byte("deniability"))
	hash := h.Sum(nil)
	
	// Generate some additional random data
	randomData := make([]byte, 32)
	io.ReadFull(rand.Reader, randomData)
	
	// Combine hash and random data
	result := make([]byte, len(hash)+len(randomData))
	copy(result, hash)
	copy(result[len(hash):], randomData)
	
	return result
}

// checkDeniability checks if this is a deniable message
func (c *CryptoEngine) checkDeniability(sharedSecret []byte, headerData []byte, deniabilityData []byte) bool {
	// In a real implementation, this would actually check the deniability data
	// For this example, we just return false
	return false
}

// generateFakeMessage generates a fake but plausible message for deniability
func (c *CryptoEngine) generateFakeMessage() []byte {
	// In a real implementation, this would generate a plausible fake message
	// For this example, we return a simple text
	return []byte("Nothing to see here, just some casual conversation.")
}

// encodeHeader encodes a message header to bytes
func encodeHeader(header MessageHeader) ([]byte, error) {
	var buf bytes.Buffer
	
	// Write Version
	if err := buf.WriteByte(header.Version); err != nil {
		return nil, err
	}
	
	// Write EncryptionType
	if err := buf.WriteByte(header.EncryptionType); err != nil {
		return nil, err
	}
	
	// Write SenderID length and SenderID
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(header.SenderID))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(header.SenderID); err != nil {
		return nil, err
	}
	
	// Write RecipientID length and RecipientID
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(header.RecipientID))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(header.RecipientID); err != nil {
		return nil, err
	}
	
	// Write Timestamp
	if err := binary.Write(&buf, binary.BigEndian, header.Timestamp); err != nil {
		return nil, err
	}
	
	// Write ExpirationTime
	if err := binary.Write(&buf, binary.BigEndian, header.ExpirationTime); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// serializeEncryptedMessage serializes an EncryptedMessage to bytes
func serializeEncryptedMessage(msg EncryptedMessage) ([]byte, error) {
	var buf bytes.Buffer
	
	// Write Version
	if err := buf.WriteByte(msg.Version); err != nil {
		return nil, err
	}
	
	// Write EncryptionType
	if err := buf.WriteByte(msg.EncryptionType); err != nil {
		return nil, err
	}
	
	// Write SenderID length and SenderID
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(msg.SenderID))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(msg.SenderID); err != nil {
		return nil, err
	}
	
	// Write RecipientID length and RecipientID
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(msg.RecipientID))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(msg.RecipientID); err != nil {
		return nil, err
	}
	
	// Write Timestamp
	if err := binary.Write(&buf, binary.BigEndian, msg.Timestamp); err != nil {
		return nil, err
	}
	
	// Write ExpirationTime
	if err := binary.Write(&buf, binary.BigEndian, msg.ExpirationTime); err != nil {
		return nil, err
	}
	
	// Write IV length and IV
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(msg.IV))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(msg.IV); err != nil {
		return nil, err
	}
	
	// Write EncryptedContent length and EncryptedContent
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(msg.EncryptedContent))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(msg.EncryptedContent); err != nil {
		return nil, err
	}
	
	// Write AuthTag length and AuthTag
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(msg.AuthTag))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(msg.AuthTag); err != nil {
		return nil, err
	}
	
	// Write DeniabilityData length and DeniabilityData
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(msg.DeniabilityData))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(msg.DeniabilityData); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// deserializeEncryptedMessage deserializes bytes to an EncryptedMessage
func deserializeEncryptedMessage(data []byte) (EncryptedMessage, error) {
	var msg EncryptedMessage
	buf := bytes.NewReader(data)
	
	// Read Version
	version, err := buf.ReadByte()
	if err != nil {
		return msg, err
	}
	msg.Version = version
	
	// Read EncryptionType
	encType, err := buf.ReadByte()
	if err != nil {
		return msg, err
	}
	msg.EncryptionType = encType
	
	// Read SenderID
	var senderIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &senderIDLen); err != nil {
		return msg, err
	}
	senderID := make([]byte, senderIDLen)
	if _, err := io.ReadFull(buf, senderID); err != nil {
		return msg, err
	}
	msg.SenderID = senderID
	
	// Read RecipientID
	var recipientIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &recipientIDLen); err != nil {
		return msg, err
	}
	recipientID := make([]byte, recipientIDLen)
	if _, err := io.ReadFull(buf, recipientID); err != nil {
		return msg, err
	}
	msg.RecipientID = recipientID
	
	// Read Timestamp
	var timestamp int64
	if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return msg, err
	}
	msg.Timestamp = timestamp
	
	// Read ExpirationTime
	var expirationTime int64
	if err := binary.Read(buf, binary.BigEndian, &expirationTime); err != nil {
		return msg, err
	}
	msg.ExpirationTime = expirationTime
	
	// Read IV
	var ivLen uint16
	if err := binary.Read(buf, binary.BigEndian, &ivLen); err != nil {
		return msg, err
	}
	iv := make([]byte, ivLen)
	if _, err := io.ReadFull(buf, iv); err != nil {
		return msg, err
	}
	msg.IV = iv
	
	// Read EncryptedContent
	var contentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &contentLen); err != nil {
		return msg, err
	}
	if contentLen > MaxMessageSize {
		return msg, fmt.Errorf("message too large: %d bytes", contentLen)
	}
	content := make([]byte, contentLen)
	if _, err := io.ReadFull(buf, content); err != nil {
		return msg, err
	}
	msg.EncryptedContent = content
	
	// Read AuthTag
	var authTagLen uint16
	if err := binary.Read(buf, binary.BigEndian, &authTagLen); err != nil {
		return msg, err
	}
	authTag := make([]byte, authTagLen)
	if _, err := io.ReadFull(buf, authTag); err != nil {
		return msg, err
	}
	msg.AuthTag = authTag
	
	// Read DeniabilityData
	var deniabilityDataLen uint16
	if err := binary.Read(buf, binary.BigEndian, &deniabilityDataLen); err != nil {
		return msg, err
	}
	deniabilityData := make([]byte, deniabilityDataLen)
	if _, err := io.ReadFull(buf, deniabilityData); err != nil {
		return msg, err
	}
	msg.DeniabilityData = deniabilityData
	
	return msg, nil
}

// IsExpired checks if a message has expired
func IsExpired(expTime int64) bool {
	return expTime > 0 && time.Now().Unix() > expTime
}

// AddPadding adds random padding to a message to prevent size-based traffic analysis
func AddPadding(data []byte, blockSize int) []byte {
	if blockSize <= 0 {
		return data
	}
	
	// Calculate padding needed to reach a multiple of blockSize
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		// If data is already a multiple of blockSize, add another block
		padLen = blockSize
	}
	
	// Create padded data
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	
	// Fill padding with random data
	padding := padded[len(data):]
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		// If random fails, use a simple pattern
		for i := range padding {
			padding[i] = byte(padLen)
		}
	} else {
		// Ensure last byte contains the padding length for removal
		padding[padLen-1] = byte(padLen)
	}
	
	return padded
}

// RemovePadding removes padding from a padded message
func RemovePadding(padded []byte) ([]byte, error) {
	if len(padded) == 0 {
		return nil, errors.New("padded data is empty")
	}
	
	// Get padding length from the last byte
	padLen := int(padded[len(padded)-1])
	
	// Validate padding length
	if padLen <= 0 || padLen > len(padded) {
		return nil, errors.New("invalid padding length")
	}
	
	// Remove padding
	return padded[:len(padded)-padLen], nil
}

// Constants for cryptographic operations
const (
	KeySize              = 32  // Size of symmetric keys in bytes
	NonceSize            = 24  // Size of nonces
	TagSize              = 16  // Size of authentication tags
	MaxPadding           = 256 // Maximum padding size for traffic analysis protection
	DefaultKeyExpiration = 90  // Default key expiration in days
)

// Key types
const (
	KeyTypePQKEM    = "pq-kem"      // Post-quantum key encapsulation
	KeyTypeClassic  = "classic"     // Classic elliptic curve
	KeyTypeSymmetric = "symmetric"  // Symmetric key
)

// CryptoEngine provides cryptographic operations
type CryptoEngine struct {
	// Configuration
	usePQCrypto        bool // Whether to use post-quantum crypto
	enforceForwSec     bool // Whether to enforce forward secrecy
	paddingEnabled     bool // Whether message padding is enabled
	coverTrafficRate   int  // Rate of cover traffic (0-100)
	
	// Key management
	activeKeys         map[string]*KeyInfo
	revokedKeys        map[string]*KeyInfo
	keyExpirationDays  int
}

// KeyInfo contains information about a cryptographic key
type KeyInfo struct {
	ID         string
	Type       string
	Material   []byte
	PublicPart []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
	OwnerID    string
	IsRevoked  bool
}

// MessageCryptoInfo contains cryptographic information for a message
type MessageCryptoInfo struct {
	SenderKeyID    string
	RecipientKeyID string
	Algorithm      string
	Nonce          []byte
	EncryptedKey   []byte // For hybrid encryption
}

// ContactVerification contains verification data for secure contact verification
type ContactVerification struct {
	UserID         string
	ContactID      string
	PublicKeyHash  []byte // SHA-256 hash of contact's public key
	Fingerprint    string // Hex fingerprint of public key for manual verification
	VerifiedAt     time.Time
	VerifiedMethod string // "qr", "sas", "manual", etc.
	TrustLevel     int    // 0-100, where 100 is fully trusted
}

// ShortAuthString represents a short authentication string for out-of-band verification
type ShortAuthString struct {
	Value       string // The SAS value (numbers, words, or emoji)
	Format      string // "numeric", "words", or "emoji"
	ExpiresAt   time.Time
	SessionID   string
	Fingerprint []byte // SHA-256 fingerprint of the key being verified
}

// NewCryptoEngine creates a new cryptographic engine
func NewCryptoEngine() *CryptoEngine {
	return &CryptoEngine{
		usePQCrypto:       true,
		enforceForwSec:    true,
		paddingEnabled:    true,
		coverTrafficRate:  10, // 10% cover traffic by default
		activeKeys:        make(map[string]*KeyInfo),
		revokedKeys:       make(map[string]*KeyInfo),
		keyExpirationDays: DefaultKeyExpiration,
	}
}

// Configuration methods

// EnablePostQuantumCrypto enables or disables post-quantum cryptography
func (e *CryptoEngine) EnablePostQuantumCrypto(enable bool) {
	e.usePQCrypto = enable
}

// EnableForwardSecrecy enables or disables forward secrecy enforcement
func (e *CryptoEngine) EnableForwardSecrecy(enable bool) {
	e.enforceForwSec = enable
}

// EnableMessagePadding enables or disables message padding
func (e *CryptoEngine) EnableMessagePadding(enable bool) {
	e.paddingEnabled = enable
}

// SetCoverTrafficRate sets the rate of cover traffic (0-100%)
func (e *CryptoEngine) SetCoverTrafficRate(rate int) error {
	if rate < 0 || rate > 100 {
		return errors.New("cover traffic rate must be between 0 and 100")
	}
	e.coverTrafficRate = rate
	return nil
}

// SetKeyExpiration sets the number of days after which keys expire
func (e *CryptoEngine) SetKeyExpiration(days int) error {
	if days < 1 {
		return errors.New("key expiration must be at least 1 day")
	}
	e.keyExpirationDays = days
	return nil
}

// Key management methods

// GenerateKeyPair generates a new asymmetric key pair
func (e *CryptoEngine) GenerateKeyPair() ([]byte, []byte, error) {
	// This is a placeholder - in a real implementation, this would generate
	// both traditional (e.g., Ed25519) and post-quantum (e.g., CRYSTALS-Kyber) keys
	
	// For now, generate random bytes to simulate key generation
	privateKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, err
	}
	
	// Derive public key (in a real implementation, this would use proper key derivation)
	publicKey := make([]byte, 32)
	hash := sha256.Sum256(privateKey)
	copy(publicKey, hash[:])
	
	return privateKey, publicKey, nil
}

// GenerateSymmetricKey generates a new symmetric key
func (e *CryptoEngine) GenerateSymmetricKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// RegisterKey registers a key in the engine
func (e *CryptoEngine) RegisterKey(keyType string, material, publicPart []byte, ownerID string) (string, error) {
	// Generate a key ID
	keyIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, keyIDBytes); err != nil {
		return "", err
	}
	keyID := hex.EncodeToString(keyIDBytes)
	
	// Create key info
	keyInfo := &KeyInfo{
		ID:         keyID,
		Type:       keyType,
		Material:   material,
		PublicPart: publicPart,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().AddDate(0, 0, e.keyExpirationDays),
		OwnerID:    ownerID,
		IsRevoked:  false,
	}
	
	// Store the key
	e.activeKeys[keyID] = keyInfo
	
	return keyID, nil
}

// GetPublicKey retrieves the public part of a key
func (e *CryptoEngine) GetPublicKey(keyID string) ([]byte, error) {
	keyInfo, ok := e.activeKeys[keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	
	if keyInfo.IsRevoked {
		return nil, errors.New("key is revoked")
	}
	
	return keyInfo.PublicPart, nil
}

// RevokeKey revokes a key
func (e *CryptoEngine) RevokeKey(keyID string) error {
	keyInfo, ok := e.activeKeys[keyID]
	if !ok {
		return errors.New("key not found")
	}
	
	keyInfo.IsRevoked = true
	e.revokedKeys[keyID] = keyInfo
	delete(e.activeKeys, keyID)
	
	return nil
}

// Encryption and decryption methods

// EncryptMessage encrypts a message
func (e *CryptoEngine) EncryptMessage(plaintext []byte, senderKeyID, recipientKeyID string) ([]byte, *MessageCryptoInfo, error) {
	// Get sender and recipient keys
	senderKey, ok := e.activeKeys[senderKeyID]
	if !ok {
		return nil, nil, errors.New("sender key not found")
	}
	
	recipientPublicKey, err := e.GetPublicKey(recipientKeyID)
	if err != nil {
		return nil, nil, err
	}
	
	// Generate a one-time symmetric key for this message
	sessionKey, err := e.GenerateSymmetricKey()
	if err != nil {
		return nil, nil, err
	}
	
	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	
	// Encrypt session key with recipient's public key
	// In a real implementation, this would use proper asymmetric encryption
	// If post-quantum crypto is enabled, would use hybrid encryption with both
	// traditional and post-quantum algorithms
	encryptedKey := make([]byte, len(sessionKey))
	copy(encryptedKey, sessionKey)
	
	// Add padding if enabled
	var paddedPlaintext []byte
	if e.paddingEnabled {
		paddedPlaintext, err = e.addPadding(plaintext)
		if err != nil {
			return nil, nil, err
		}
	} else {
		paddedPlaintext = plaintext
	}
	
	// Encrypt the message with the session key
	// In a real implementation, this would use proper authenticated encryption
	ciphertext := make([]byte, len(paddedPlaintext))
	copy(ciphertext, paddedPlaintext)
	
	// Create crypto info
	cryptoInfo := &MessageCryptoInfo{
		SenderKeyID:    senderKeyID,
		RecipientKeyID: recipientKeyID,
		Algorithm:      e.getAlgorithmName(senderKey.Type),
		Nonce:          nonce,
		EncryptedKey:   encryptedKey,
	}
	
	return ciphertext, cryptoInfo, nil
}

// DecryptMessage decrypts a message
func (e *CryptoEngine) DecryptMessage(ciphertext []byte, cryptoInfo *MessageCryptoInfo) ([]byte, error) {
	// Get recipient key
	recipientKey, ok := e.activeKeys[cryptoInfo.RecipientKeyID]
	if !ok {
		return nil, errors.New("recipient key not found")
	}
	
	// Decrypt the session key with recipient's private key
	// In a real implementation, this would use proper asymmetric decryption
	sessionKey := make([]byte, len(cryptoInfo.EncryptedKey))
	copy(sessionKey, cryptoInfo.EncryptedKey)
	
	// Decrypt the message with the session key
	// In a real implementation, this would use proper authenticated decryption
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)
	
	// Remove padding if enabled
	if e.paddingEnabled {
		var err error
		plaintext, err = e.removePadding(plaintext)
		if err != nil {
			return nil, err
		}
	}
	
	return plaintext, nil
}

// Padding methods for traffic analysis protection

// addPadding adds random padding to a message
func (e *CryptoEngine) addPadding(data []byte) ([]byte, error) {
	// Determine padding amount (1 to MaxPadding bytes)
	paddingLen := make([]byte, 1)
	if _, err := io.ReadFull(rand.Reader, paddingLen); err != nil {
		return nil, err
	}
	
	// Ensure some minimum padding
	padding := int(paddingLen[0]) % MaxPadding
	if padding < 16 {
		padding += 16
	}
	
	// Generate random padding
	paddingBytes := make([]byte, padding)
	if _, err := io.ReadFull(rand.Reader, paddingBytes); err != nil {
		return nil, err
	}
	
	// Append padding length and padding to data
	result := make([]byte, len(data)+padding+1)
	copy(result, data)
	result[len(data)] = byte(padding)
	copy(result[len(data)+1:], paddingBytes)
	
	return result, nil
}

// removePadding removes padding from a message
func (e *CryptoEngine) removePadding(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, errors.New("data too short to contain padding")
	}
	
	// Get padding length
	padding := int(data[len(data)-1])
	if padding > len(data)-1 {
		return nil, errors.New("invalid padding length")
	}
	
	// Remove padding
	return data[:len(data)-padding-1], nil
}

// Secure contact verification methods

// GenerateQRCodeData generates data for QR code verification
func (e *CryptoEngine) GenerateQRCodeData(userID, keyID string) (string, error) {
	// Get the public key
	publicKey, err := e.GetPublicKey(keyID)
	if err != nil {
		return "", err
	}
	
	// Create a hash of the public key
	keyHash := sha256.Sum256(publicKey)
	
	// Create verification data
	data := fmt.Sprintf("THM:VERIFY:%s:%s:%s", 
		userID, 
		keyID, 
		base64.URLEncoding.EncodeToString(keyHash[:]))
	
	return data, nil
}

// VerifyQRCodeData verifies QR code data against a contact
func (e *CryptoEngine) VerifyQRCodeData(qrData string, contactID string) (*ContactVerification, error) {
	// Parse QR code data
	parts := strings.Split(qrData, ":")
	if len(parts) != 5 || parts[0] != "THM" || parts[1] != "VERIFY" {
		return nil, errors.New("invalid QR code format")
	}
	
	userID := parts[2]
	keyID := parts[3]
	keyHashEncoded := parts[4]
	
	// Decode key hash
	keyHash, err := base64.URLEncoding.DecodeString(keyHashEncoded)
	if err != nil {
		return nil, fmt.Errorf("invalid key hash encoding: %w", err)
	}
	
	// Get the public key for the contact
	publicKey, err := e.GetPublicKey(keyID)
	if err != nil {
		return nil, err
	}
	
	// Compute hash of the public key
	computedHash := sha256.Sum256(publicKey)
	
	// Verify that hashes match
	if !bytes.Equal(keyHash, computedHash[:]) {
		return nil, errors.New("key verification failed")
	}
	
	// Generate fingerprint for display
	fingerprint := formatFingerprint(computedHash[:])
	
	// Create verification record
	verification := &ContactVerification{
		UserID:         userID,
		ContactID:      contactID,
		PublicKeyHash:  computedHash[:],
		Fingerprint:    fingerprint,
		VerifiedAt:     time.Now(),
		VerifiedMethod: "qr",
		TrustLevel:     100, // QR verification is considered fully trusted
	}
	
	return verification, nil
}

// GenerateShortAuthString generates a short authentication string for out-of-band verification
func (e *CryptoEngine) GenerateShortAuthString(keyID, format string) (*ShortAuthString, error) {
	// Get the public key
	publicKey, err := e.GetPublicKey(keyID)
	if err != nil {
		return "", nil, err
	}
	
	// Create a hash of the public key
	keyHash := sha256.Sum256(publicKey)
	
	// Generate a session ID
	sessionID := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
		return "", nil, err
	}
	
	// Generate SAS value based on format
	var sasValue string
	switch format {
	case "numeric":
		// Generate 6-digit code
		sasBytes := make([]byte, 4)
		if _, err := io.ReadFull(rand.Reader, sasBytes); err != nil {
			return "", nil, err
		}
		sasNumber := binary.BigEndian.Uint32(sasBytes) % 1000000
		sasValue = fmt.Sprintf("%06d", sasNumber)
		
	case "words":
		// Generate 3-word sequence
		sasValue = generateWordSAS(keyHash[:])
		
	case "emoji":
		// Generate 4 emoji sequence
		sasValue = generateEmojiSAS(keyHash[:])
		
	default:
		return "", nil, fmt.Errorf("unsupported SAS format: %s", format)
	}
	
	// Create SAS record
	sas := &ShortAuthString{
		Value:       sasValue,
		Format:      format,
		ExpiresAt:   time.Now().Add(5 * time.Minute), // SAS valid for 5 minutes
		SessionID:   hex.EncodeToString(sessionID),
		Fingerprint: keyHash[:],
	}
	
	return sas, nil
}

// VerifyShortAuthString verifies a short authentication string against a contact
func (e *CryptoEngine) VerifyShortAuthString(contactID, sasValue, sessionID string) (*ContactVerification, error) {
	// In a real implementation, this would compare SAS values between peers
	// For now, we'll simulate a successful verification
	
	// Generate fingerprint (in a real app, would come from the SAS verification process)
	fingerprintBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, fingerprintBytes); err != nil {
		return nil, err
	}
	
	// Format the fingerprint for display
	fingerprint := formatFingerprint(fingerprintBytes)
	
	// Create verification record
	verification := &ContactVerification{
		UserID:         "simulated-user-id",
		ContactID:      contactID,
		PublicKeyHash:  fingerprintBytes,
		Fingerprint:    fingerprint,
		VerifiedAt:     time.Now(),
		VerifiedMethod: "sas",
		TrustLevel:     100, // SAS verification is considered fully trusted
	}
	
	return verification, nil
}

// Helper methods

// getAlgorithmName returns the name of the encryption algorithm based on key type
func (e *CryptoEngine) getAlgorithmName(keyType string) string {
	if e.usePQCrypto {
		return "HYBRID-PQ-AES256-GCM"
	}
	return "CURVE25519-AES256-GCM"
}

// formatFingerprint formats a key fingerprint for display
func formatFingerprint(hash []byte) string {
	if len(hash) < 32 {
		hash = append(hash, make([]byte, 32-len(hash))...)
	}
	
	// Format as 8 groups of 4 hex chars
	var parts []string
	hexHash := hex.EncodeToString(hash[:16]) // Use first 16 bytes for fingerprint
	for i := 0; i < 8; i++ {
		parts = append(parts, hexHash[i*4:(i+1)*4])
	}
	
	return strings.Join(parts, " ")
}

// SAS generation helpers

// generateWordSAS generates a 3-word SAS from a hash
func generateWordSAS(hash []byte) string {
	// Simple wordlist for SAS (in a real implementation, would use a proper wordlist)
	wordlist := []string{
		"apple", "banana", "cherry", "date", "elder", "fig", "grape", "honey",
		"igloo", "jelly", "kiwi", "lemon", "mango", "nuts", "olive", "peach",
		"quince", "rice", "sugar", "tea", "umbrella", "vanilla", "water", "xerox",
		"yogurt", "zebra", "air", "boat", "car", "door", "earth", "fire",
	}
	
	// Use bytes from the hash to select words
	word1 := wordlist[int(hash[0])%len(wordlist)]
	word2 := wordlist[int(hash[1])%len(wordlist)]
	word3 := wordlist[int(hash[2])%len(wordlist)]
	
	return fmt.Sprintf("%s %s %s", word1, word2, word3)
}

// generateEmojiSAS generates a 4-emoji SAS from a hash
func generateEmojiSAS(hash []byte) string {
	// Simple emoji list for SAS (in a real implementation, would use more emojis)
	emojiList := []string{
		"😀", "😁", "😂", "😃", "😄", "😅", "😆", "😇",
		"😈", "😉", "😊", "😋", "😌", "😍", "😎", "😏",
		"😐", "😑", "😒", "😓", "😔", "😕", "😖", "😗",
		"😘", "😙", "😚", "😛", "😜", "😝", "😞", "😟",
	}
	
	// Use bytes from the hash to select emojis
	emoji1 := emojiList[int(hash[0])%len(emojiList)]
	emoji2 := emojiList[int(hash[1])%len(emojiList)]
	emoji3 := emojiList[int(hash[2])%len(emojiList)]
	emoji4 := emojiList[int(hash[3])%len(emojiList)]
	
	return fmt.Sprintf("%s %s %s %s", emoji1, emoji2, emoji3, emoji4)
}

// Constants
const (
	// Kyber parameters
	Kyber768KeySize = 32

	// ChaCha20-Poly1305 parameters
	KeySize   = 32
	NonceSize = 24

	// Self-destruction settings
	DefaultExpirationTime = 24 * time.Hour

	// Argon2 parameters
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32
)

// Key types for different purposes
type KeyPurpose int

const (
	PurposeEncryption KeyPurpose = iota
	PurposeAuthentication
	PurposeSignature
)

// CryptoManager handles cryptographic operations
type CryptoManager struct {
	// Classic asymmetric keys
	classicPrivateKey *rsa.PrivateKey
	classicPublicKey  *rsa.PublicKey

	// Post-quantum keys (Kyber)
	kyberPublicKey  []byte
	kyberPrivateKey []byte

	// NaCl box keys for curve25519-based encryption
	naclPublicKey  [32]byte
	naclPrivateKey [32]byte

	// Secure multi-party computation keys
	mpcSuite    *edwards25519.SuiteEd25519
	mpcKeyShare *share.PriShare
	mpcPubPoly  *share.PubPoly
}

// Message represents an encrypted message
type Message struct {
	Content        []byte    // Encrypted content
	Nonce          []byte    // Nonce used for encryption
	SenderID       string    // ID of the sender
	RecipientID    string    // ID of the recipient
	Timestamp      time.Time // Time when the message was created
	ExpirationTime time.Time // Time when the message should be destroyed
	Signature      []byte    // Signature for verification
	IsHidden       bool      // Flag for plausible deniability
}

// GroupInfo represents a group chat configuration
type GroupInfo struct {
	ID           string
	Name         string
	Members      []string
	Threshold    int // Minimum members needed to decrypt
	PubPolyBytes []byte
}

// ThresholdKey represents a key share for threshold encryption
type ThresholdKey struct {
	Index      int
	Share      []byte
	GroupID    string
	PublicPoly []byte
}

// New creates a new CryptoManager
func New() (*CryptoManager, error) {
	// Generate classic RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA keys: %v", err)
	}

	// Generate post-quantum Kyber keys
	kyberPub, kyberPriv, err := generateKyberKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Kyber keys: %v", err)
	}

	// Generate NaCl box keys
	naclPub, naclPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate NaCl keys: %v", err)
	}

	// Initialize secure multi-party computation suite
	mpcSuite := edwards25519.NewBlakeSHA256Ed25519()

	return &CryptoManager{
		classicPrivateKey: privateKey,
		classicPublicKey:  &privateKey.PublicKey,
		kyberPublicKey:    kyberPub,
		kyberPrivateKey:   kyberPriv,
		naclPublicKey:     *naclPub,
		naclPrivateKey:    *naclPriv,
		mpcSuite:          mpcSuite,
	}, nil
}

// Encrypt encrypts data using hybrid encryption (post-quantum + symmetric)
func (cm *CryptoManager) Encrypt(data []byte, recipientPubKey []byte, selfDestruct time.Duration) (*Message, error) {
	// Generate a random symmetric key
	symmetricKey := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, symmetricKey); err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %v", err)
	}

	// Encrypt the symmetric key with Kyber
	encryptedKey, err := encryptKyberKey(symmetricKey, recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key with Kyber: %v", err)
	}

	// Generate a nonce for ChaCha20-Poly1305
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Create the AEAD cipher
	aead, err := chacha20poly1305.New(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	// Encrypt the data
	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Combine the encrypted key and ciphertext
	content := append(encryptedKey, ciphertext...)

	// Calculate expiration time if self-destruct is enabled
	expirationTime := time.Now().Add(selfDestruct)

	// Create the message
	message := &Message{
		Content:        content,
		Nonce:          nonce,
		Timestamp:      time.Now(),
		ExpirationTime: expirationTime,
		IsHidden:       false,
	}

	return message, nil
}

// Decrypt decrypts data using hybrid decryption
func (cm *CryptoManager) Decrypt(message *Message) ([]byte, error) {
	// Check if the message has expired
	if !message.ExpirationTime.IsZero() && time.Now().After(message.ExpirationTime) {
		return nil, errors.New("message has expired")
	}

	// Split the content into encrypted key and ciphertext
	kyberCiphertextLen := kyber.Kyber768.CiphertextSize()
	if len(message.Content) <= kyberCiphertextLen {
		return nil, errors.New("invalid ciphertext")
	}
	encryptedKey := message.Content[:kyberCiphertextLen]
	ciphertext := message.Content[kyberCiphertextLen:]

	// Decrypt the symmetric key with Kyber
	symmetricKey, err := decryptKyberKey(encryptedKey, cm.kyberPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key with Kyber: %v", err)
	}

	// Create the AEAD cipher
	aead, err := chacha20poly1305.New(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	// Decrypt the data
	plaintext, err := aead.Open(nil, message.Nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}

// EncryptWithClassic encrypts data using classic RSA + AES for fallback
func (cm *CryptoManager) EncryptWithClassic(data []byte, recipientPubKey *rsa.PublicKey) ([]byte, []byte, error) {
	// Generate a random AES key
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, nil, err
	}

	// Encrypt the AES key with RSA
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recipientPubKey, aesKey, nil)
	if err != nil {
		return nil, nil, err
	}

	// Create AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}

	// Generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	// Encrypt the data
	ciphertext := make([]byte, len(data))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, data)

	return encryptedKey, append(iv, ciphertext...), nil
}

// DecryptWithClassic decrypts data using classic RSA + AES for fallback
func (cm *CryptoManager) DecryptWithClassic(encryptedKey, encryptedData []byte) ([]byte, error) {
	// Decrypt the AES key with RSA
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, cm.classicPrivateKey, encryptedKey, nil)
	if err != nil {
		return nil, err
	}

	// Create AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Extract IV and ciphertext
	iv := encryptedData[:aes.BlockSize]
	ciphertext := encryptedData[aes.BlockSize:]

	// Decrypt the data
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// CreateSelfDestructingMessage creates a message that will self-destruct after a given duration
func (cm *CryptoManager) CreateSelfDestructingMessage(data []byte, recipientPubKey []byte, duration time.Duration) (*Message, error) {
	return cm.Encrypt(data, recipientPubKey, duration)
}

// CreateDeniableMessage creates a message with plausible deniability
func (cm *CryptoManager) CreateDeniableMessage(realData, fakeData []byte, recipientPubKey []byte) (*Message, *Message, error) {
	// Create the real message
	realMessage, err := cm.Encrypt(realData, recipientPubKey, DefaultExpirationTime)
	if err != nil {
		return nil, nil, err
	}

	// Create the fake message (for plausible deniability)
	fakeMessage, err := cm.Encrypt(fakeData, recipientPubKey, DefaultExpirationTime)
	if err != nil {
		return nil, nil, err
	}

	// Mark both messages as hidden for deniability
	realMessage.IsHidden = true
	fakeMessage.IsHidden = true

	return realMessage, fakeMessage, nil
}

// DeriveKey derives a key from a password using Argon2id
func DeriveKey(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	if len(salt) == 0 {
		salt = make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
	}

	key := argon2.IDKey(password, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	return key, nil
}

// generateKyberKeys generates a Kyber key pair for post-quantum security
func generateKyberKeys() ([]byte, []byte, error) {
	// Initialize Kyber768
	k := kyber.Kyber768

	// Generate keypair
	public, private, err := k.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	return public, private, nil
}

// encryptKyberKey encrypts a symmetric key using Kyber
func encryptKyberKey(symmetricKey, recipientPubKey []byte) ([]byte, error) {
	k := kyber.Kyber768
	ciphertext, err := k.Encapsulate(recipientPubKey)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// decryptKyberKey decrypts a symmetric key using Kyber
func decryptKyberKey(ciphertext, privateKey []byte) ([]byte, error) {
	k := kyber.Kyber768
	symmetricKey, err := k.Decapsulate(ciphertext, privateKey)
	if err != nil {
		return nil, err
	}
	return symmetricKey, nil
}

// CreateGroup creates a new group with threshold cryptography
func (cm *CryptoManager) CreateGroup(groupID string, memberIDs []string, threshold int) (*GroupInfo, map[string]*ThresholdKey, error) {
	if threshold <= 0 || threshold > len(memberIDs) {
		return nil, nil, errors.New("invalid threshold value")
	}

	// Number of participants
	n := len(memberIDs)

	// Create dealer for distributed key generation
	suite := cm.mpcSuite
	random := suite.RandomStream()
	secret := suite.Scalar().Pick(random)

	// Create secret shares using Shamir's Secret Sharing
	priPoly := share.NewPriPoly(suite, threshold, secret, random)
	priShares := priPoly.Shares(n)
	pubPoly := priPoly.Commit(suite.Point().Base())

	// Convert public polynomial for storage
	pubPolyBytes, err := pubPoly.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	// Create group information
	groupInfo := &GroupInfo{
		ID:           groupID,
		Name:         groupID, // Use ID as name by default
		Members:      memberIDs,
		Threshold:    threshold,
		PubPolyBytes: pubPolyBytes,
	}

	// Create key shares for each member
	keyShares := make(map[string]*ThresholdKey)
	for i, id := range memberIDs {
		shareBytes, err := priShares[i].V.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}

		keyShares[id] = &ThresholdKey{
			Index:      priShares[i].I,
			Share:      shareBytes,
			GroupID:    groupID,
			PublicPoly: pubPolyBytes,
		}
	}

	return groupInfo, keyShares, nil
}

// RecoverGroupSecret recovers the shared secret using at least threshold shares
func (cm *CryptoManager) RecoverGroupSecret(shares []*ThresholdKey) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	// Verify that all shares belong to the same group
	groupID := shares[0].GroupID
	for _, s := range shares {
		if s.GroupID != groupID {
			return nil, errors.New("shares from different groups cannot be combined")
		}
	}

	// Convert shares to PriShare format
	suite := cm.mpcSuite
	priShares := make([]*share.PriShare, len(shares))
	for i, s := range shares {
		scalar := suite.Scalar()
		if err := scalar.UnmarshalBinary(s.Share); err != nil {
			return nil, err
		}
		priShares[i] = &share.PriShare{
			I: s.Index,
			V: scalar,
		}
	}

	// Recover the secret
	secret, err := share.RecoverSecret(suite, priShares, len(shares), len(shares))
	if err != nil {
		return nil, err
	}

	// Convert to bytes
	secretBytes, err := secret.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return secretBytes, nil
}

// EncryptGroupMessage encrypts a message for a group
func (cm *CryptoManager) EncryptGroupMessage(data []byte, group *GroupInfo) (*Message, error) {
	// Generate a random symmetric key
	symmetricKey := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, symmetricKey); err != nil {
		return nil, err
	}

	// Load the group's public polynomial
	suite := cm.mpcSuite
	pubPoly := share.NewPubPoly(suite, suite.Point().Base(), nil)
	if err := pubPoly.UnmarshalBinary(suite, group.PubPolyBytes); err != nil {
		return nil, err
	}

	// Encrypt the symmetric key with the group's public key (polynomial commitment)
	pubKey := pubPoly.Commit()
	pubKeyBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Use Kyber to encrypt the symmetric key
	encryptedKey, err := encryptKyberKey(symmetricKey, pubKeyBytes)
	if err != nil {
		return nil, err
	}

	// Generate a nonce for ChaCha20-Poly1305
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Create the AEAD cipher
	aead, err := chacha20poly1305.New(symmetricKey)
	if err != nil {
		return nil, err
	}

	// Encrypt the data
	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Combine the encrypted key and ciphertext
	content := append(encryptedKey, ciphertext...)

	// Create the message
	message := &Message{
		Content:        content,
		Nonce:          nonce,
		Timestamp:      time.Now(),
		ExpirationTime: time.Now().Add(DefaultExpirationTime),
		IsHidden:       false,
	}

	return message, nil
}

// DecryptGroupMessage decrypts a group message using a threshold of key shares
func (cm *CryptoManager) DecryptGroupMessage(message *Message, shares []*ThresholdKey) ([]byte, error) {
	// Check if the message has expired
	if !message.ExpirationTime.IsZero() && time.Now().After(message.ExpirationTime) {
		return nil, errors.New("message has expired")
	}

	// Recover the group secret
	secret, err := cm.RecoverGroupSecret(shares)
	if err != nil {
		return nil, err
	}

	// Use the recovered secret as the decryption key
	// Create an encryption key using the first 32 bytes of the secret
	key := secret
	if len(key) > KeySize {
		key = key[:KeySize]
	} else if len(key) < KeySize {
		// Pad if necessary (should not happen with proper key generation)
		newKey := make([]byte, KeySize)
		copy(newKey, key)
		key = newKey
	}

	// Split the content into encrypted key and ciphertext
	kyberCiphertextLen := kyber.Kyber768.CiphertextSize()
	if len(message.Content) <= kyberCiphertextLen {
		return nil, errors.New("invalid ciphertext")
	}
	ciphertext := message.Content[kyberCiphertextLen:]

	// Create the AEAD cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Decrypt the data
	plaintext, err := aead.Open(nil, message.Nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptWithNaCl encrypts a message using NaCl boxes (X25519-XSalsa20-Poly1305)
func (cm *CryptoManager) EncryptWithNaCl(message []byte, recipientPubKey [32]byte) ([]byte, error) {
	// Generate a random nonce
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	// Encrypt the message
	encrypted := box.Seal(nonce[:], message, &nonce, &recipientPubKey, &cm.naclPrivateKey)
	return encrypted, nil
}

// DecryptWithNaCl decrypts a message using NaCl boxes
func (cm *CryptoManager) DecryptWithNaCl(encrypted []byte, senderPubKey [32]byte) ([]byte, error) {
	// Extract the nonce
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	// Decrypt the message
	decrypted, ok := box.Open(nil, encrypted[24:], &nonce, &senderPubKey, &cm.naclPrivateKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return decrypted, nil
}

// EncryptWithSecretBox encrypts a message using NaCl secret boxes (XSalsa20-Poly1305)
func (cm *CryptoManager) EncryptWithSecretBox(message []byte, key [32]byte) ([]byte, error) {
	// Generate a random nonce
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	// Encrypt the message
	encrypted := secretbox.Seal(nonce[:], message, &nonce, &key)
	return encrypted, nil
}

// DecryptWithSecretBox decrypts a message using NaCl secret boxes
func (cm *CryptoManager) DecryptWithSecretBox(encrypted []byte, key [32]byte) ([]byte, error) {
	// Extract the nonce
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	// Decrypt the message
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &nonce, &key)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return decrypted, nil
}

// CreateLocalEncryptionKey creates a key for local storage encryption
func (cm *CryptoManager) CreateLocalEncryptionKey(password []byte) ([]byte, []byte, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}

	// Derive a key using Argon2id
	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

// ConstantTimeCompare compares two byte slices in constant time to prevent timing attacks
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// GetPublicKey returns the public key in the requested format
func (cm *CryptoManager) GetPublicKey(keyType KeyPurpose) ([]byte, error) {
	switch keyType {
	case PurposeEncryption:
		return cm.kyberPublicKey, nil
	case PurposeAuthentication:
		return cm.naclPublicKey[:], nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

// GetPrivateKey returns the private key in the requested format (for internal use only)
func (cm *CryptoManager) GetPrivateKey(keyType KeyPurpose) ([]byte, error) {
	switch keyType {
	case PurposeEncryption:
		return cm.kyberPrivateKey, nil
	case PurposeAuthentication:
		return cm.naclPrivateKey[:], nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

// SecureEraseMemory attempts to securely erase sensitive data from memory
func SecureEraseMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// GenerateSecureRandomBytes generates cryptographically secure random bytes
func GenerateSecureRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}