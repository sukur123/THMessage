package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// SecureStorage handles all encrypted data storage for THMessage
type SecureStorage struct {
	baseDir       string
	masterKey     []byte
	keyDerivation KeyDerivationConfig
	mutex         sync.RWMutex
	isOpen        bool
}

// KeyDerivationConfig contains settings for the password-based key derivation
type KeyDerivationConfig struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// Message represents a stored message
type Message struct {
	ID           string
	SenderID     string
	RecipientID  string
	Content      []byte
	Timestamp    int64
	IsRead       bool
	IsExpired    bool
	ExpirationTS int64
}

// DefaultKeyDerivationConfig returns secure default settings for key derivation
func DefaultKeyDerivationConfig() KeyDerivationConfig {
	return KeyDerivationConfig{
		Memory:      64 * 1024, // 64MB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// NewSecureStorage creates a new secure storage instance
func NewSecureStorage() (*SecureStorage, error) {
	// Create base directory for storage
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	baseDir := filepath.Join(homeDir, ".thmessage")
	err = os.MkdirAll(baseDir, 0700) // Only user can access
	if err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Create message directory
	msgDir := filepath.Join(baseDir, "messages")
	err = os.MkdirAll(msgDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create messages directory: %w", err)
	}

	// Create keys directory
	keysDir := filepath.Join(baseDir, "keys")
	err = os.MkdirAll(keysDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	return &SecureStorage{
		baseDir:       baseDir,
		keyDerivation: DefaultKeyDerivationConfig(),
		isOpen:        false,
	}, nil
}

// Open unlocks the secure storage with the user's password
func (s *SecureStorage) Open(password []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.isOpen {
		return errors.New("storage is already open")
	}

	// Check if this is first-time setup
	saltPath := filepath.Join(s.baseDir, "salt")
	if _, err := os.Stat(saltPath); os.IsNotExist(err) {
		// First time setup - generate new salt and master key
		return s.initializeStorage(password)
	}

	// Read the salt
	salt, err := os.ReadFile(saltPath)
	if err != nil {
		return fmt.Errorf("failed to read salt: %w", err)
	}

	// Derive the key encryption key (KEK) from the password
	kek := argon2.IDKey(
		password,
		salt,
		s.keyDerivation.Iterations,
		s.keyDerivation.Memory,
		s.keyDerivation.Parallelism,
		s.keyDerivation.KeyLength,
	)

	// Read the encrypted master key
	encKeyPath := filepath.Join(s.baseDir, "master.key")
	encryptedKey, err := os.ReadFile(encKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted master key: %w", err)
	}

	// Decrypt the master key
	if len(encryptedKey) < 12+16 { // nonce + tag size minimum
		return errors.New("invalid encrypted master key format")
	}

	// Extract nonce
	nonce := encryptedKey[:12]
	ciphertext := encryptedKey[12:]

	// Create cipher
	block, err := aes.NewCipher(kek)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Decrypt
	masterKey, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return errors.New("invalid password or corrupted master key")
	}

	s.masterKey = masterKey
	s.isOpen = true
	return nil
}

// initializeStorage sets up storage for first-time use
func (s *SecureStorage) initializeStorage(password []byte) error {
	// Generate a random salt
	salt := make([]byte, s.keyDerivation.SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Save the salt
	saltPath := filepath.Join(s.baseDir, "salt")
	if err := os.WriteFile(saltPath, salt, 0600); err != nil {
		return fmt.Errorf("failed to write salt: %w", err)
	}

	// Derive the key encryption key from the password
	kek := argon2.IDKey(
		password,
		salt,
		s.keyDerivation.Iterations,
		s.keyDerivation.Memory,
		s.keyDerivation.Parallelism,
		s.keyDerivation.KeyLength,
	)

	// Generate a random master key
	masterKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Encrypt the master key with the KEK
	block, err := aes.NewCipher(kek)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt master key
	encryptedKey := aesgcm.Seal(nonce, nonce, masterKey, nil)

	// Save encrypted master key
	encKeyPath := filepath.Join(s.baseDir, "master.key")
	if err := os.WriteFile(encKeyPath, encryptedKey, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted master key: %w", err)
	}

	s.masterKey = masterKey
	s.isOpen = true
	return nil
}

// Close securely closes the storage and wipes sensitive data from memory
func (s *SecureStorage) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isOpen {
		return nil
	}

	// Securely wipe the master key from memory
	if s.masterKey != nil {
		for i := range s.masterKey {
			s.masterKey[i] = 0
		}
		s.masterKey = nil
	}

	s.isOpen = false
	return nil
}

// ChangePassword changes the master password
func (s *SecureStorage) ChangePassword(oldPassword, newPassword []byte) error {
	// First verify the old password is correct by trying to unlock
	if !s.isOpen {
		if err := s.Open(oldPassword); err != nil {
			return err
		}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Generate a new salt
	salt := make([]byte, s.keyDerivation.SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Save the new salt
	saltPath := filepath.Join(s.baseDir, "salt")
	if err := os.WriteFile(saltPath, salt, 0600); err != nil {
		return fmt.Errorf("failed to write salt: %w", err)
	}

	// Derive the new key encryption key
	kek := argon2.IDKey(
		newPassword,
		salt,
		s.keyDerivation.Iterations,
		s.keyDerivation.Memory,
		s.keyDerivation.Parallelism,
		s.keyDerivation.KeyLength,
	)

	// Encrypt the master key with the new KEK
	block, err := aes.NewCipher(kek)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt master key
	encryptedKey := aesgcm.Seal(nonce, nonce, s.masterKey, nil)

	// Save encrypted master key
	encKeyPath := filepath.Join(s.baseDir, "master.key")
	if err := os.WriteFile(encKeyPath, encryptedKey, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted master key: %w", err)
	}

	return nil
}

// StoreMessage encrypts and stores a message with the provided ID
func (s *SecureStorage) StoreMessage(message *Message) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isOpen {
		return errors.New("storage is not open")
	}

	// Serialize the message
	var buf bytes.Buffer
	
	// Write sender ID length and data
	senderIDBytes := []byte(message.SenderID)
	binary.Write(&buf, binary.BigEndian, uint16(len(senderIDBytes)))
	buf.Write(senderIDBytes)
	
	// Write recipient ID length and data
	recipientIDBytes := []byte(message.RecipientID)
	binary.Write(&buf, binary.BigEndian, uint16(len(recipientIDBytes)))
	buf.Write(recipientIDBytes)
	
	// Write timestamp
	binary.Write(&buf, binary.BigEndian, message.Timestamp)
	
	// Write flags (isRead, isExpired)
	var flags byte
	if message.IsRead {
		flags |= 1
	}
	if message.IsExpired {
		flags |= 2
	}
	buf.WriteByte(flags)
	
	// Write expiration timestamp
	binary.Write(&buf, binary.BigEndian, message.ExpirationTS)
	
	// Write content length and data
	binary.Write(&buf, binary.BigEndian, uint32(len(message.Content)))
	buf.Write(message.Content)

	// Encrypt the serialized message
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Create a message-specific nonce based on the message ID and timestamp
	// This makes it deterministic but unique for each message
	nonceBase := message.ID + fmt.Sprintf("%d", message.Timestamp)
	nonceHash := sha256.Sum256([]byte(nonceBase))
	nonce := nonceHash[:12]

	// Encrypt the message
	encryptedData := aesgcm.Seal(nil, nonce, buf.Bytes(), nil)

	// Create the final message file format: [nonce][encrypted data]
	fileData := make([]byte, len(nonce)+len(encryptedData))
	copy(fileData, nonce)
	copy(fileData[len(nonce):], encryptedData)

	// Write to the messages directory
	msgPath := filepath.Join(s.baseDir, "messages", message.ID)
	if err := os.WriteFile(msgPath, fileData, 0600); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}

	return nil
}

// GetMessage retrieves and decrypts a message by ID
func (s *SecureStorage) GetMessage(messageID string) (*Message, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.isOpen {
		return nil, errors.New("storage is not open")
	}

	// Read the message file
	msgPath := filepath.Join(s.baseDir, "messages", messageID)
	fileData, err := os.ReadFile(msgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read message file: %w", err)
	}

	// Need at least a nonce
	if len(fileData) < 12 {
		return nil, errors.New("invalid message file format")
	}

	// Extract nonce and ciphertext
	nonce := fileData[:12]
	ciphertext := fileData[12:]

	// Decrypt the message
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Decrypt
	decrypted, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	// Deserialize the message
	buf := bytes.NewReader(decrypted)

	// Read sender ID
	var senderIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &senderIDLen); err != nil {
		return nil, fmt.Errorf("failed to read sender ID length: %w", err)
	}
	senderIDBytes := make([]byte, senderIDLen)
	if _, err := io.ReadFull(buf, senderIDBytes); err != nil {
		return nil, fmt.Errorf("failed to read sender ID: %w", err)
	}
	
	// Read recipient ID
	var recipientIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &recipientIDLen); err != nil {
		return nil, fmt.Errorf("failed to read recipient ID length: %w", err)
	}
	recipientIDBytes := make([]byte, recipientIDLen)
	if _, err := io.ReadFull(buf, recipientIDBytes); err != nil {
		return nil, fmt.Errorf("failed to read recipient ID: %w", err)
	}
	
	// Read timestamp
	var timestamp int64
	if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return nil, fmt.Errorf("failed to read timestamp: %w", err)
	}
	
	// Read flags
	flags, err := buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read flags: %w", err)
	}
	isRead := (flags & 1) != 0
	isExpired := (flags & 2) != 0
	
	// Read expiration timestamp
	var expirationTS int64
	if err := binary.Read(buf, binary.BigEndian, &expirationTS); err != nil {
		return nil, fmt.Errorf("failed to read expiration timestamp: %w", err)
	}
	
	// Check if message has expired (if not already marked as expired)
	if !isExpired && expirationTS > 0 && expirationTS < time.Now().Unix() {
		isExpired = true
		
		// Update the message status in storage
		// This is done asynchronously to avoid blocking the read operation
		go func() {
			msg := &Message{
				ID:           messageID,
				SenderID:     string(senderIDBytes),
				RecipientID:  string(recipientIDBytes),
				Timestamp:    timestamp,
				IsRead:       isRead,
				IsExpired:    true,
				ExpirationTS: expirationTS,
			}
			s.StoreMessage(msg) // Update with expired flag
		}()
	}
	
	// Read content
	var contentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &contentLen); err != nil {
		return nil, fmt.Errorf("failed to read content length: %w", err)
	}
	content := make([]byte, contentLen)
	if _, err := io.ReadFull(buf, content); err != nil {
		return nil, fmt.Errorf("failed to read content: %w", err)
	}

	// Construct message object
	message := &Message{
		ID:           messageID,
		SenderID:     string(senderIDBytes),
		RecipientID:  string(recipientIDBytes),
		Content:      content,
		Timestamp:    timestamp,
		IsRead:       isRead,
		IsExpired:    isExpired,
		ExpirationTS: expirationTS,
	}

	return message, nil
}

// ListMessages returns a list of all message IDs
func (s *SecureStorage) ListMessages() ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.isOpen {
		return nil, errors.New("storage is not open")
	}

	// Read the messages directory
	msgDir := filepath.Join(s.baseDir, "messages")
	entries, err := os.ReadDir(msgDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read messages directory: %w", err)
	}

	// Extract message IDs
	msgIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			msgIDs = append(msgIDs, entry.Name())
		}
	}

	return msgIDs, nil
}

// DeleteMessage permanently deletes a message
func (s *SecureStorage) DeleteMessage(messageID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isOpen {
		return errors.New("storage is not open")
	}

	// Securely delete the message file by overwriting it with random data
	msgPath := filepath.Join(s.baseDir, "messages", messageID)
	
	// Get file size
	fileInfo, err := os.Stat(msgPath)
	if err != nil {
		return fmt.Errorf("failed to stat message file: %w", err)
	}
	
	// Open the file for writing
	file, err := os.OpenFile(msgPath, os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open message file for secure deletion: %w", err)
	}
	defer file.Close()
	
	// Overwrite with random data
	randomData := make([]byte, 4096) // Use a reasonable buffer size
	remaining := fileInfo.Size()
	
	for remaining > 0 {
		bufSize := int64(len(randomData))
		if remaining < bufSize {
			bufSize = remaining
		}
		
		// Generate random data
		if _, err := io.ReadFull(rand.Reader, randomData[:bufSize]); err != nil {
			return fmt.Errorf("failed to generate random data for secure deletion: %w", err)
		}
		
		// Write to file
		if _, err := file.Write(randomData[:bufSize]); err != nil {
			return fmt.Errorf("failed to overwrite message file: %w", err)
		}
		
		remaining -= bufSize
	}
	
	// Sync to ensure data is written to disk
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file during secure deletion: %w", err)
	}
	
	// Now delete the file
	if err := os.Remove(msgPath); err != nil {
		return fmt.Errorf("failed to delete message file: %w", err)
	}

	return nil
}

// StoreKeyPair stores user's encryption keys securely
func (s *SecureStorage) StoreKeyPair(userID string, privateKey, publicKey []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isOpen {
		return errors.New("storage is not open")
	}

	// Encrypt the private key with the master key
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt private key
	encryptedPrivKey := aesgcm.Seal(nil, nonce, privateKey, nil)

	// Create directories for user keys
	userDir := filepath.Join(s.baseDir, "keys", userID)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return fmt.Errorf("failed to create user key directory: %w", err)
	}

	// Write the private key: [nonce][encrypted private key]
	privKeyData := make([]byte, len(nonce)+len(encryptedPrivKey))
	copy(privKeyData, nonce)
	copy(privKeyData[len(nonce):], encryptedPrivKey)

	privKeyPath := filepath.Join(userDir, "private.key")
	if err := os.WriteFile(privKeyPath, privKeyData, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write the public key (no need to encrypt)
	pubKeyPath := filepath.Join(userDir, "public.key")
	if err := os.WriteFile(pubKeyPath, publicKey, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// GetPrivateKey retrieves and decrypts a user's private key
func (s *SecureStorage) GetPrivateKey(userID string) ([]byte, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.isOpen {
		return nil, errors.New("storage is not open")
	}

	// Read the private key file
	privKeyPath := filepath.Join(s.baseDir, "keys", userID, "private.key")
	fileData, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Need at least a nonce
	if len(fileData) < 12 {
		return nil, errors.New("invalid private key file format")
	}

	// Extract nonce and ciphertext
	nonce := fileData[:12]
	ciphertext := fileData[12:]

	// Decrypt the private key
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Decrypt
	privateKey, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	return privateKey, nil
}

// GetPublicKey retrieves a user's public key
func (s *SecureStorage) GetPublicKey(userID string) ([]byte, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.isOpen {
		return nil, errors.New("storage is not open")
	}

	// Read the public key file
	pubKeyPath := filepath.Join(s.baseDir, "keys", userID, "public.key")
	publicKey, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	return publicKey, nil
}

// CreateHiddenVolume creates a separate hidden storage volume that can be revealed
// only with a separate password (for plausible deniability)
func (s *SecureStorage) CreateHiddenVolume(hiddenPassword []byte) error {
	// This would be implemented in a real system. For now just a placeholder.
	return errors.New("hidden volumes not implemented yet")
}

// StorageEngine handles secure data storage
type StorageEngine struct {
	rootPath      string
	hiddenSpaces  map[string]*HiddenSpace
	activeSpace   string
	secureDelete  bool
	overwritePasses int
}

// HiddenSpace represents a separate data storage area that requires separate credentials
type HiddenSpace struct {
	ID             string
	Name           string
	KeyDerivationSalt []byte
	MasterKeyHash  []byte
	CreatedAt      time.Time
	LastAccessedAt time.Time
	Path           string
	IsActive       bool
}

// StoredMessage represents a message in storage
type StoredMessage struct {
	ID             string
	SenderID       string
	RecipientID    string
	Timestamp      time.Time
	ExpiresAt      *time.Time
	Content        []byte
	CryptoInfo     []byte
	ReadAt         *time.Time
	SelfDestruct   bool
	FilePath       string
}

// StorageOptions configures the storage engine
type StorageOptions struct {
	SecureDelete    bool
	OverwritePasses int
	RootPath        string
}

// NewStorageEngine creates a new storage engine
func NewStorageEngine(options StorageOptions) (*StorageEngine, error) {
	if options.OverwritePasses <= 0 {
		options.OverwritePasses = 3 // Default to 3 passes for secure deletion
	}
	
	if options.RootPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		options.RootPath = filepath.Join(homeDir, ".thmessage")
	}
	
	// Ensure the root directory exists
	if err := os.MkdirAll(options.RootPath, 0700); err != nil {
		return nil, err
	}
	
	// Create storage engine
	engine := &StorageEngine{
		rootPath:       options.RootPath,
		hiddenSpaces:   make(map[string]*HiddenSpace),
		activeSpace:    "default",
		secureDelete:   options.SecureDelete,
		overwritePasses: options.OverwritePasses,
	}
	
	// Ensure the default space exists
	defaultSpacePath := filepath.Join(options.RootPath, "default")
	if err := os.MkdirAll(defaultSpacePath, 0700); err != nil {
		return nil, err
	}
	
	// Create required subdirectories
	for _, dir := range []string{"messages", "contacts", "keys", "media"} {
		if err := os.MkdirAll(filepath.Join(defaultSpacePath, dir), 0700); err != nil {
			return nil, err
		}
	}
	
	return engine, nil
}

// CreateHiddenSpace creates a new hidden space with separate credentials
func (e *StorageEngine) CreateHiddenSpace(name, password string) (*HiddenSpace, error) {
	// Generate a random ID for the space
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return nil, err
	}
	spaceID := hex.EncodeToString(idBytes)
	
	// Generate a salt for key derivation
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	
	// Derive a master key from the password (in reality, would use a proper KDF like Argon2)
	passwordBytes := []byte(password)
	combined := append(passwordBytes, salt...)
	keyHash := sha256.Sum256(combined)
	
	// Create the space's directory
	spacePath := filepath.Join(e.rootPath, spaceID)
	if err := os.MkdirAll(spacePath, 0700); err != nil {
		return nil, err
	}
	
	// Create required subdirectories
	for _, dir := range []string{"messages", "contacts", "keys", "media"} {
		if err := os.MkdirAll(filepath.Join(spacePath, dir), 0700); err != nil {
			return nil, err
		}
	}
	
	// Create the hidden space
	space := &HiddenSpace{
		ID:             spaceID,
		Name:           name,
		KeyDerivationSalt: salt,
		MasterKeyHash:  keyHash[:],
		CreatedAt:      time.Now(),
		LastAccessedAt: time.Now(),
		Path:           spacePath,
		IsActive:       false,
	}
	
	// Add to hidden spaces
	e.hiddenSpaces[spaceID] = space
	
	return space, nil
}

// UnlockHiddenSpace unlocks and activates a hidden space
func (e *StorageEngine) UnlockHiddenSpace(spaceID, password string) error {
	space, exists := e.hiddenSpaces[spaceID]
	if !exists {
		return errors.New("hidden space not found")
	}
	
	// Derive key from password and check against stored hash
	passwordBytes := []byte(password)
	combined := append(passwordBytes, space.KeyDerivationSalt...)
	keyHash := sha256.Sum256(combined)
	
	if !compareHashes(keyHash[:], space.MasterKeyHash) {
		return errors.New("incorrect password")
	}
	
	// Activate the space
	space.IsActive = true
	space.LastAccessedAt = time.Now()
	e.activeSpace = spaceID
	
	return nil
}

// SwitchToSpace switches to a different space (default or hidden)
func (e *StorageEngine) SwitchToSpace(spaceID string) error {
	if spaceID == "default" {
		e.activeSpace = "default"
		return nil
	}
	
	space, exists := e.hiddenSpaces[spaceID]
	if !exists {
		return errors.New("hidden space not found")
	}
	
	if !space.IsActive {
		return errors.New("hidden space is locked")
	}
	
	e.activeSpace = spaceID
	return nil
}

// LockHiddenSpace locks a hidden space
func (e *StorageEngine) LockHiddenSpace(spaceID string) error {
	space, exists := e.hiddenSpaces[spaceID]
	if !exists {
		return errors.New("hidden space not found")
	}
	
	space.IsActive = false
	
	// If this was the active space, switch to default
	if e.activeSpace == spaceID {
		e.activeSpace = "default"
	}
	
	return nil
}

// GetCurrentSpacePath returns the path to the current active space
func (e *StorageEngine) GetCurrentSpacePath() string {
	if e.activeSpace == "default" {
		return filepath.Join(e.rootPath, "default")
	}
	
	space, exists := e.hiddenSpaces[e.activeSpace]
	if !exists {
		// Fallback to default if space doesn't exist
		return filepath.Join(e.rootPath, "default")
	}
	
	return space.Path
}

// Secure deletion methods

// SecureDeleteFile securely deletes a file by overwriting its contents before unlinking
func (e *StorageEngine) SecureDeleteFile(filePath string) error {
	// Check if secure deletion is enabled
	if !e.secureDelete {
		// If not, just remove the file normally
		return os.Remove(filePath)
	}
	
	// Open the file
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Get file size
	info, err := file.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	
	// Overwrite with random data multiple times
	buffer := make([]byte, 8192) // 8KB buffer
	for pass := 0; pass < e.overwritePasses; pass++ {
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}
		
		bytesWritten := int64(0)
		for bytesWritten < size {
			// Fill buffer with random data
			if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
				return err
			}
			
			// Write the buffer
			writeSize := buffer
			if int64(len(buffer)) > size-bytesWritten {
				writeSize = buffer[:size-bytesWritten]
			}
			
			n, err := file.Write(writeSize)
			if err != nil {
				return err
			}
			bytesWritten += int64(n)
		}
		
		// Flush to disk
		if err := file.Sync(); err != nil {
			return err
		}
	}
	
	// Close the file
	if err := file.Close(); err != nil {
		return err
	}
	
	// Finally, remove the file
	return os.Remove(filePath)
}

// SecureDeleteDirectory securely deletes an entire directory and its contents
func (e *StorageEngine) SecureDeleteDirectory(dirPath string) error {
	// Walk through all files in the directory
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip directories (for now)
		if info.IsDir() {
			return nil
		}
		
		// Securely delete each file
		if err := e.SecureDeleteFile(path); err != nil {
			return err
		}
		
		return nil
	})
	
	if err != nil {
		return err
	}
	
	// Now remove the empty directories
	return os.RemoveAll(dirPath)
}

// DeleteMessage deletes a message, with secure deletion if enabled
func (e *StorageEngine) DeleteMessage(messageID string) error {
	// Get message file path (in a real implementation, this would look up the message in a database)
	spacePath := e.GetCurrentSpacePath()
	msgPath := filepath.Join(spacePath, "messages", messageID+".msg")
	
	// Check if the file exists
	if _, err := os.Stat(msgPath); os.IsNotExist(err) {
		return errors.New("message not found")
	}
	
	// Securely delete the message
	return e.SecureDeleteFile(msgPath)
}

// Helper methods

// compareHashes compares two hashes in constant time to prevent timing attacks
func compareHashes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	
	return result == 0
}