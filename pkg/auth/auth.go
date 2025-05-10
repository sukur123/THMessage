package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/pbkdf2"
	
	"thmessage/pkg/crypto"
	"thmessage/pkg/storage"
)

// OPAQUECredentials represents the OPAQUE protocol credentials
type OPAQUECredentials struct {
	UserID            string
	RegistrationRecord []byte
	UserPrivateKey    []byte
	ServerPublicKey   []byte
}

// AuthSession represents an active authentication session
type AuthSession struct {
	SessionID  string
	UserID     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	DeviceInfo string
	IPAddress  string
}

// AuthManager handles user authentication
type AuthManager struct {
	crypto      *crypto.CryptoEngine
	storage     *storage.SecureStorage
	sessions    map[string]*AuthSession // In-memory session storage
	useHardware bool                    // Whether to use hardware-backed authentication
}

// User represents a user in the system
type User struct {
	ID                string
	Username          string
	PasswordVerifier  []byte // OPAQUE verifier - not the actual password
	Salt              []byte
	PublicKey         []byte
	RecoveryData      []byte // Encrypted recovery data
	DuressCredentials []byte // For plausible deniability (hidden access)
	Settings          map[string]string
	CreatedAt         time.Time
	VerifierKey       []byte // OPAQUE server verifier
	PrivateKey        []byte // Encrypted with user's master key
}

// HardwareAuthInfo contains information for hardware token authentication
type HardwareAuthInfo struct {
	TokenType    string // "u2f", "webauthn", etc.
	CredentialID []byte
	PublicKey    []byte
}

// VerificationMethod represents different ways users can verify their identity
type VerificationMethod struct {
	Type        string // "password", "hardware", "recovery_code"
	HashedValue []byte // For password: hashed password, for others: credential ID
	Salt        []byte // For password
	LastUsed    time.Time
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(crypto *crypto.CryptoEngine, storage *storage.SecureStorage) (*AuthManager, error) {
	return &AuthManager{
		crypto:      crypto,
		storage:     storage,
		sessions:    make(map[string]*AuthSession),
		useHardware: false, // Default to no hardware authentication
	}, nil
}

// RegisterUser creates a new user with password-based authentication
func (a *AuthManager) RegisterUser(username, password string) (*User, error) {
	// Generate a unique user ID
	userID, err := a.generateUserID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %w", err)
	}

	// Generate key pair for the user
	privateKey, publicKey, err := a.crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create password verification
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash the password with Argon2id
	hashedPassword := argon2.IDKey(
		[]byte(password),
		salt,
		3,         // Time cost
		64*1024,   // Memory cost (64MB)
		4,         // Parallelism
		32,        // Output key length
	)

	// Create a new user
	user := &User{
		ID:         userID,
		Username:   username,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		CreatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	// Create verification method
	verificationMethod := &VerificationMethod{
		Type:        "password",
		HashedValue: hashedPassword,
		Salt:        salt,
		LastUsed:    time.Now(),
	}

	// Store the user's key pair
	if err := a.storage.StoreKeyPair(userID, privateKey, publicKey); err != nil {
		return nil, fmt.Errorf("failed to store key pair: %w", err)
	}

	// Store user and verification info
	// This would typically involve saving to a database, but for simplicity
	// we'll use our existing storage mechanism
	if err := a.storeUserAndVerification(user, verificationMethod); err != nil {
		return nil, fmt.Errorf("failed to store user: %w", err)
	}

	return user, nil
}

// RegisterUserWithOPAQUE creates a new user with OPAQUE zero-knowledge authentication
func (a *AuthManager) RegisterUserWithOPAQUE(username string, clientRegistration []byte) (*User, error) {
	// In a complete implementation, this would process OPAQUE registration
	// For now, we'll create a placeholder implementation
	
	// Generate a unique user ID
	userID, err := a.generateUserID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %w", err)
	}

	// Generate key pair for the user
	privateKey, publicKey, err := a.crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// In a real OPAQUE implementation, we would:
	// 1. Process the client registration message
	// 2. Generate a server key pair
	// 3. Create and store the registration record
	// 4. Return the server public key to the client
	
	// For now, we'll simulate the OPAQUE registration record
	opaqueCredentials := &OPAQUECredentials{
		UserID:            userID,
		RegistrationRecord: clientRegistration, // In reality, this would be processed
		UserPrivateKey:    privateKey,
		ServerPublicKey:   []byte("simulated-server-public-key"),
	}

	// Create a new user
	user := &User{
		ID:         userID,
		Username:   username,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		CreatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	// Create verification method (for OPAQUE)
	verificationMethod := &VerificationMethod{
		Type:        "opaque",
		HashedValue: []byte("opaque-verification"), // Placeholder
		Salt:        []byte{},                      // Not used in OPAQUE
		LastUsed:    time.Now(),
	}

	// Store the user's key pair
	if err := a.storage.StoreKeyPair(userID, privateKey, publicKey); err != nil {
		return nil, fmt.Errorf("failed to store key pair: %w", err)
	}

	// Store user and verification info
	if err := a.storeUserAndVerification(user, verificationMethod); err != nil {
		return nil, fmt.Errorf("failed to store user: %w", err)
	}

	// Store OPAQUE credentials
	if err := a.storeOPAQUECredentials(opaqueCredentials); err != nil {
		return nil, fmt.Errorf("failed to store OPAQUE credentials: %w", err)
	}

	return user, nil
}

// RegisterHardwareToken registers a hardware security token for a user
func (a *AuthManager) RegisterHardwareToken(userID string, tokenInfo *HardwareAuthInfo) error {
	// In a real implementation, this would handle WebAuthn/U2F registration
	// For now, we'll implement a simplified version
	
	if !a.useHardware {
		return errors.New("hardware authentication is not enabled")
	}
	
	// Create verification method for hardware token
	verificationMethod := &VerificationMethod{
		Type:        "hardware",
		HashedValue: tokenInfo.CredentialID, // Store credential ID for lookup
		LastUsed:    time.Now(),
	}
	
	// Store hardware token info
	if err := a.storeHardwareToken(userID, tokenInfo); err != nil {
		return fmt.Errorf("failed to store hardware token: %w", err)
	}
	
	// Add this verification method to the user
	if err := a.addVerificationMethod(userID, verificationMethod); err != nil {
		return fmt.Errorf("failed to add verification method: %w", err)
	}
	
	return nil
}

// Login authenticates a user with username and password
func (a *AuthManager) Login(username, password string) (string, error) {
	// Find the user by username
	user, err := a.findUserByUsername(username)
	if err != nil {
		return "", fmt.Errorf("authentication failed: %w", err)
	}
	
	// Get the user's verification methods
	verificationMethods, err := a.getVerificationMethods(user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to get verification methods: %w", err)
	}
	
	// Find the password verification method
	var passwordMethod *VerificationMethod
	for _, method := range verificationMethods {
		if method.Type == "password" {
			passwordMethod = method
			break
		}
	}
	
	if passwordMethod == nil {
		return "", errors.New("no password verification method found for user")
	}
	
	// Verify the password
	hashedPassword := argon2.IDKey(
		[]byte(password),
		passwordMethod.Salt,
		3,         // Time cost
		64*1024,   // Memory cost
		4,         // Parallelism
		32,        // Output key length
	)
	
	if !bytes.Equal(hashedPassword, passwordMethod.HashedValue) {
		return "", errors.New("invalid password")
	}
	
	// Update last used time
	passwordMethod.LastUsed = time.Now()
	if err := a.updateVerificationMethod(user.ID, passwordMethod); err != nil {
		// Non-fatal but should be logged
		fmt.Printf("Failed to update verification method: %v\n", err)
	}
	
	// Create a new session
	sessionID, err := a.createSession(user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	
	// Update user's last seen time
	user.LastSeen = time.Now()
	if err := a.updateUser(user); err != nil {
		// Non-fatal but should be logged
		fmt.Printf("Failed to update user last seen: %v\n", err)
	}
	
	return sessionID, nil
}

// LoginWithOPAQUE authenticates a user using the OPAQUE protocol
func (a *AuthManager) LoginWithOPAQUE(username string, clientMessage []byte) (string, []byte, error) {
	// In a complete implementation, this would:
	// 1. Process the client's initial authentication message
	// 2. Retrieve the user's OPAQUE registration record
	// 3. Compute the server authentication message
	// 4. Verify the client's proof of key
	// 5. Create a new session if successful
	
	// Find the user by username
	user, err := a.findUserByUsername(username)
	if err != nil {
		return "", nil, fmt.Errorf("authentication failed: %w", err)
	}
	
	// Get the OPAQUE credentials
	opaqueCredentials, err := a.getOPAQUECredentials(user.ID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get OPAQUE credentials: %w", err)
	}
	
	// In a real implementation, process the OPAQUE protocol here
	// For now, we'll simulate a successful authentication
	
	// Create a simulated server response
	serverResponse := []byte("simulated-opaque-server-response")
	
	// Create a new session
	sessionID, err := a.createSession(user.ID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create session: %w", err)
	}
	
	// Update user's last seen time
	user.LastSeen = time.Now()
	if err := a.updateUser(user); err != nil {
		// Non-fatal but should be logged
		fmt.Printf("Failed to update user last seen: %v\n", err)
	}
	
	return sessionID, serverResponse, nil
}

// LoginWithHardwareToken authenticates a user using a hardware security token
func (a *AuthManager) LoginWithHardwareToken(username string, authResponse []byte) (string, error) {
	if (!a.useHardware) {
		return "", errors.New("hardware authentication is not enabled")
	}
	
	// Find the user by username
	user, err := a.findUserByUsername(username)
	if err != nil {
		return "", fmt.Errorf("authentication failed: %w", err)
	}
	
	// Get the user's hardware tokens
	tokens, err := a.getHardwareTokens(user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to get hardware tokens: %w", err)
	}
	
	if len(tokens) == 0 {
		return "", errors.New("no hardware tokens registered for user")
	}
	
	// In a real implementation, this would:
	// 1. Verify the WebAuthn/U2F assertion
	// 2. Check the signature against the stored public key
	// 3. Verify the token's counter to prevent replay attacks
	
	// For now, we'll simulate a successful verification
	
	// Create a new session
	sessionID, err := a.createSession(user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	
	// Update user's last seen time
	user.LastSeen = time.Now()
	if err := a.updateUser(user); err != nil {
		// Non-fatal but should be logged
		fmt.Printf("Failed to update user last seen: %v\n", err)
	}
	
	return sessionID, nil
}

// Logout terminates a user session
func (a *AuthManager) Logout(sessionID string) error {
	a.deleteSession(sessionID)
	return nil
}

// GetUserFromSession returns the user associated with a session
func (a *AuthManager) GetUserFromSession(sessionID string) (*User, error) {
	// Find the session
	session, ok := a.sessions[sessionID]
	if !ok {
		return nil, errors.New("invalid or expired session")
	}
	
	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		a.deleteSession(sessionID)
		return nil, errors.New("session has expired")
	}
	
	// Get the user
	user, err := a.findUserByID(session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	
	return user, nil
}

// ChangePassword changes a user's password
func (a *AuthManager) ChangePassword(userID, oldPassword, newPassword string) error {
	// Get the user's verification methods
	verificationMethods, err := a.getVerificationMethods(userID)
	if err != nil {
		return fmt.Errorf("failed to get verification methods: %w", err)
	}
	
	// Find the password verification method
	var passwordMethod *VerificationMethod
	for _, method := range verificationMethods {
		if method.Type == "password" {
			passwordMethod = method
			break
		}
	}
	
	if passwordMethod == nil {
		return errors.New("no password verification method found for user")
	}
	
	// Verify the old password
	oldHashedPassword := argon2.IDKey(
		[]byte(oldPassword),
		passwordMethod.Salt,
		3,         // Time cost
		64*1024,   // Memory cost
		4,         // Parallelism
		32,        // Output key length
	)
	
	if !bytes.Equal(oldHashedPassword, passwordMethod.HashedValue) {
		return errors.New("invalid old password")
	}
	
	// Generate new salt
	newSalt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	
	// Hash the new password
	newHashedPassword := argon2.IDKey(
		[]byte(newPassword),
		newSalt,
		3,         // Time cost
		64*1024,   // Memory cost
		4,         // Parallelism
		32,        // Output key length
	)
	
	// Update the verification method
	passwordMethod.HashedValue = newHashedPassword
	passwordMethod.Salt = newSalt
	passwordMethod.LastUsed = time.Now()
	
	if err := a.updateVerificationMethod(userID, passwordMethod); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	
	return nil
}

// GenerateRecoveryCodes generates recovery codes for a user
func (a *AuthManager) GenerateRecoveryCodes(userID string) ([]string, error) {
	// Generate 8 recovery codes
	recoveryCodes := make([]string, 8)
	for i := 0; i < 8; i++ {
		// Generate 16 bytes of random data
		randomBytes := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
			return nil, fmt.Errorf("failed to generate recovery code: %w", err)
		}
		
		// Format as 4 groups of 5 characters
		code := base64.RawURLEncoding.EncodeToString(randomBytes)[:20]
		recoveryCodes[i] = fmt.Sprintf("%s-%s-%s-%s", 
			code[0:5], code[5:10], code[10:15], code[15:20])
		
		// Hash the code for storage
		codeHash := sha256.Sum256([]byte(recoveryCodes[i]))
		
		// Store each recovery code as a verification method
		verificationMethod := &VerificationMethod{
			Type:        "recovery_code",
			HashedValue: codeHash[:],
			LastUsed:    time.Time{}, // Never used
		}
		
		if err := a.addVerificationMethod(userID, verificationMethod); err != nil {
			return nil, fmt.Errorf("failed to store recovery code: %w", err)
		}
	}
	
	return recoveryCodes, nil
}

// RecoverAccount allows a user to regain access using a recovery code
func (a *AuthManager) RecoverAccount(username, recoveryCode string) (string, error) {
	// Find the user by username
	user, err := a.findUserByUsername(username)
	if err != nil {
		return "", fmt.Errorf("recovery failed: %w", err)
	}
	
	// Get the user's verification methods
	verificationMethods, err := a.getVerificationMethods(user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to get verification methods: %w", err)
	}
	
	// Hash the provided recovery code
	codeHash := sha256.Sum256([]byte(recoveryCode))
	
	// Look for a matching recovery code
	var matchedMethod *VerificationMethod
	for _, method := range verificationMethods {
		if method.Type == "recovery_code" && bytes.Equal(method.HashedValue, codeHash[:]) {
			matchedMethod = method
			break
		}
	}
	
	if matchedMethod == nil {
		return "", errors.New("invalid recovery code")
	}
	
	// Check if code has been used
	if !matchedMethod.LastUsed.IsZero() {
		return "", errors.New("recovery code has already been used")
	}
	
	// Mark the recovery code as used
	matchedMethod.LastUsed = time.Now()
	if err := a.updateVerificationMethod(user.ID, matchedMethod); err != nil {
		// Non-fatal but should be logged
		fmt.Printf("Failed to mark recovery code as used: %v\n", err)
	}
	
	// Create a new session
	sessionID, err := a.createSession(user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	
	return sessionID, nil
}

// EnableHardwareAuth enables hardware token authentication
func (a *AuthManager) EnableHardwareAuth() {
	a.useHardware = true
}

// Helper methods
func (a *AuthManager) generateUserID() (string, error) {
	// Generate 16 random bytes
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return "", err
	}
	
	// Format as hex string
	return fmt.Sprintf("%x", idBytes), nil
}

func (a *AuthManager) createSession(userID string) (string, error) {
	// Generate session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, sessionIDBytes); err != nil {
		return "", err
	}
	sessionID := fmt.Sprintf("%x", sessionIDBytes)
	
	// Create session
	session := &AuthSession{
		SessionID:  sessionID,
		UserID:     userID,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour), // Sessions last 24 hours
		DeviceInfo: "unknown",                      // In a real app, this would be populated
		IPAddress:  "unknown",                      // In a real app, this would be populated
	}
	
	// Store session
	a.sessions[sessionID] = session
	
	return sessionID, nil
}

func (a *AuthManager) deleteSession(sessionID string) {
	delete(a.sessions, sessionID)
}

// In a real implementation, the following methods would interact with a database
// For this example, we'll use the storage package and simulate some of the operations

func (a *AuthManager) storeUserAndVerification(user *User, method *VerificationMethod) error {
	// In a real app, this would store in a user database
	// For now, we'll create a simplified storage using our existing secure storage
	
	// Serialize the user
	userBytes, err := serializeUser(user)
	if err != nil {
		return err
	}
	
	// Store in the secure storage
	userKey := fmt.Sprintf("user:%s", user.ID)
	userMessage := &storage.Message{
		ID:          userKey,
		SenderID:    "system",
		RecipientID: "system",
		Content:     userBytes,
		Timestamp:   time.Now().Unix(),
	}
	
	if err := a.storage.StoreMessage(userMessage); err != nil {
		return err
	}
	
	// Also store by username for lookup
	usernameKey := fmt.Sprintf("username:%s", user.Username)
	usernameMessage := &storage.Message{
		ID:          usernameKey,
		SenderID:    "system",
		RecipientID: "system",
		Content:     []byte(user.ID),
		Timestamp:   time.Now().Unix(),
	}
	
	if err := a.storage.StoreMessage(usernameMessage); err != nil {
		return err
	}
	
	// Serialize the verification method
	methodBytes, err := serializeVerificationMethod(method)
	if err != nil {
		return err
	}
	
	// Store in the secure storage
	methodKey := fmt.Sprintf("verification:%s:%s", user.ID, method.Type)
	methodMessage := &storage.Message{
		ID:          methodKey,
		SenderID:    "system",
		RecipientID: "system",
		Content:     methodBytes,
		Timestamp:   time.Now().Unix(),
	}
	
	return a.storage.StoreMessage(methodMessage)
}

func (a *AuthManager) storeOPAQUECredentials(credentials *OPAQUECredentials) error {
	// Serialize the credentials
	credBytes, err := serializeOPAQUECredentials(credentials)
	if err != nil {
		return err
	}
	
	// Store in the secure storage
	credKey := fmt.Sprintf("opaque:%s", credentials.UserID)
	credMessage := &storage.Message{
		ID:          credKey,
		SenderID:    "system",
		RecipientID: "system",
		Content:     credBytes,
		Timestamp:   time.Now().Unix(),
	}
	
	return a.storage.StoreMessage(credMessage)
}

func (a *AuthManager) getOPAQUECredentials(userID string) (*OPAQUECredentials, error) {
	credKey := fmt.Sprintf("opaque:%s", userID)
	credMessage, err := a.storage.GetMessage(credKey)
	if err != nil {
		return nil, err
	}
	
	return deserializeOPAQUECredentials(credMessage.Content)
}

func (a *AuthManager) storeHardwareToken(userID string, token *HardwareAuthInfo) error {
	// Serialize the token
	tokenBytes, err := serializeHardwareAuthInfo(token)
	if err != nil {
		return err
	}
	
	// Generate a unique ID for this token
	tokenID := fmt.Sprintf("%x", token.CredentialID[:8])
	
	// Store in the secure storage
	tokenKey := fmt.Sprintf("hardware:%s:%s", userID, tokenID)
	tokenMessage := &storage.Message{
		ID:          tokenKey,
		SenderID:    "system",
		RecipientID: "system",
		Content:     tokenBytes,
		Timestamp:   time.Now().Unix(),
	}
	
	return a.storage.StoreMessage(tokenMessage)
}

func (a *AuthManager) getHardwareTokens(userID string) ([]*HardwareAuthInfo, error) {
	// In a real app, this would query the database for tokens
	// For now, we'll simulate it using our list messages function
	
	// Get all messages
	msgIDs, err := a.storage.ListMessages()
	if err != nil {
		return nil, err
	}
	
	// Filter for hardware tokens
	prefix := fmt.Sprintf("hardware:%s:", userID)
	var tokens []*HardwareAuthInfo
	
	for _, id := range msgIDs {
		if len(id) > len(prefix) && id[:len(prefix)] == prefix {
			msg, err := a.storage.GetMessage(id)
			if err != nil {
				return nil, err
			}
			
			token, err := deserializeHardwareAuthInfo(msg.Content)
			if err != nil {
				return nil, err
			}
			
			tokens = append(tokens, token)
		}
	}
	
	return tokens, nil
}

func (a *AuthManager) addVerificationMethod(userID string, method *VerificationMethod) error {
	// Serialize the verification method
	methodBytes, err := serializeVerificationMethod(method)
	if err != nil {
		return err
	}
	
	// Store in the secure storage
	// For recovery codes (which can have multiple), use a random suffix
	methodType := method.Type
	if methodType == "recovery_code" {
		randBytes := make([]byte, 4)
		io.ReadFull(rand.Reader, randBytes)
		methodType = fmt.Sprintf("%s:%x", methodType, randBytes)
	}
	
	methodKey := fmt.Sprintf("verification:%s:%s", userID, methodType)
	methodMessage := &storage.Message{
		ID:          methodKey,
		SenderID:    "system",
		RecipientID: "system",
		Content:     methodBytes,
		Timestamp:   time.Now().Unix(),
	}
	
	return a.storage.StoreMessage(methodMessage)
}

func (a *AuthManager) updateVerificationMethod(userID string, method *VerificationMethod) error {
	// Simply overwrite the existing method
	methodBytes, err := serializeVerificationMethod(method)
	if err != nil {
		return err
	}
	
	methodKey := fmt.Sprintf("verification:%s:%s", userID, method.Type)
	methodMessage := &storage.Message{
		ID:          methodKey,
		SenderID:    "system",
		RecipientID: "system",
		Content:     methodBytes,
		Timestamp:   time.Now().Unix(),
	}
	
	return a.storage.StoreMessage(methodMessage)
}

func (a *AuthManager) getVerificationMethods(userID string) ([]*VerificationMethod, error) {
	// In a real app, this would query the database for methods
	// For now, we'll simulate it using our list messages function
	
	// Get all messages
	msgIDs, err := a.storage.ListMessages()
	if err != nil {
		return nil, err
	}
	
	// Filter for verification methods
	prefix := fmt.Sprintf("verification:%s:", userID)
	var methods []*VerificationMethod
	
	for _, id := range msgIDs {
		if len(id) > len(prefix) && id[:len(prefix)] == prefix {
			msg, err := a.storage.GetMessage(id)
			if err != nil {
				return nil, err
			}
			
			method, err := deserializeVerificationMethod(msg.Content)
			if err != nil {
				return nil, err
			}
			
			methods = append(methods, method)
		}
	}
	
	return methods, nil
}

func (a *AuthManager) findUserByUsername(username string) (*User, error) {
	// Look up the user ID by username
	usernameKey := fmt.Sprintf("username:%s", username)
	usernameMsg, err := a.storage.GetMessage(usernameKey)
	if err != nil {
		return nil, errors.New("user not found")
	}
	
	// Get the user ID from the message content
	userID := string(usernameMsg.Content)
	
	return a.findUserByID(userID)
}

func (a *AuthManager) findUserByID(userID string) (*User, error) {
	userKey := fmt.Sprintf("user:%s", userID)
	userMsg, err := a.storage.GetMessage(userKey)
	if err != nil {
		return nil, errors.New("user not found")
	}
	
	return deserializeUser(userMsg.Content)
}

func (a *AuthManager) updateUser(user *User) error {
	// Serialize the user
	userBytes, err := serializeUser(user)
	if err != nil {
		return err
	}
	
	// Store in the secure storage
	userKey := fmt.Sprintf("user:%s", user.ID)
	userMessage := &storage.Message{
		ID:          userKey,
		SenderID:    "system",
		RecipientID: "system",
		Content:     userBytes,
		Timestamp:   time.Now().Unix(),
	}
	
	return a.storage.StoreMessage(userMessage)
}

// Serialization helpers

func serializeUser(user *User) ([]byte, error) {
	var buf bytes.Buffer
	
	// Write ID length and ID
	idBytes := []byte(user.ID)
	binary.Write(&buf, binary.BigEndian, uint16(len(idBytes)))
	buf.Write(idBytes)
	
	// Write Username length and Username
	usernameBytes := []byte(user.Username)
	binary.Write(&buf, binary.BigEndian, uint16(len(usernameBytes)))
	buf.Write(usernameBytes)
	
	// Write timestamps
	binary.Write(&buf, binary.BigEndian, user.CreatedAt.Unix())
	binary.Write(&buf, binary.BigEndian, user.LastSeen.Unix())
	
	return buf.Bytes(), nil
}

func deserializeUser(data []byte) (*User, error) {
	buf := bytes.NewReader(data)
	
	// Read ID
	var idLen uint16
	if err := binary.Read(buf, binary.BigEndian, &idLen); err != nil {
		return nil, err
	}
	idBytes := make([]byte, idLen)
	if _, err := io.ReadFull(buf, idBytes); err != nil {
		return nil, err
	}
	
	// Read Username
	var usernameLen uint16
	if err := binary.Read(buf, binary.BigEndian, &usernameLen); err != nil {
		return nil, err
	}
	usernameBytes := make([]byte, usernameLen)
	if _, err := io.ReadFull(buf, usernameBytes); err != nil {
		return nil, err
	}
	
	// Read timestamps
	var createdAt, lastSeen int64
	if err := binary.Read(buf, binary.BigEndian, &createdAt); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &lastSeen); err != nil {
		return nil, err
	}
	
	return &User{
		ID:        string(idBytes),
		Username:  string(usernameBytes),
		CreatedAt: time.Unix(createdAt, 0),
		LastSeen:  time.Unix(lastSeen, 0),
	}, nil
}

func serializeVerificationMethod(method *VerificationMethod) ([]byte, error) {
	var buf bytes.Buffer
	
	// Write Type length and Type
	typeBytes := []byte(method.Type)
	binary.Write(&buf, binary.BigEndian, uint16(len(typeBytes)))
	buf.Write(typeBytes)
	
	// Write HashedValue length and HashedValue
	binary.Write(&buf, binary.BigEndian, uint16(len(method.HashedValue)))
	buf.Write(method.HashedValue)
	
	// Write Salt length and Salt
	binary.Write(&buf, binary.BigEndian, uint16(len(method.Salt)))
	buf.Write(method.Salt)
	
	// Write LastUsed
	binary.Write(&buf, binary.BigEndian, method.LastUsed.Unix())
	
	return buf.Bytes(), nil
}

func deserializeVerificationMethod(data []byte) (*VerificationMethod, error) {
	buf := bytes.NewReader(data)
	
	// Read Type
	var typeLen uint16
	if err := binary.Read(buf, binary.BigEndian, &typeLen); err != nil {
		return nil, err
	}
	typeBytes := make([]byte, typeLen)
	if _, err := io.ReadFull(buf, typeBytes); err != nil {
		return nil, err
	}
	
	// Read HashedValue
	var hashedValueLen uint16
	if err := binary.Read(buf, binary.BigEndian, &hashedValueLen); err != nil {
		return nil, err
	}
	hashedValue := make([]byte, hashedValueLen)
	if _, err := io.ReadFull(buf, hashedValue); err != nil {
		return nil, err
	}
	
	// Read Salt
	var saltLen uint16
	if err := binary.Read(buf, binary.BigEndian, &saltLen); err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(buf, salt); err != nil {
		return nil, err
	}
	
	// Read LastUsed
	var lastUsed int64
	if err := binary.Read(buf, binary.BigEndian, &lastUsed); err != nil {
		return nil, err
	}
	
	return &VerificationMethod{
		Type:        string(typeBytes),
		HashedValue: hashedValue,
		Salt:        salt,
		LastUsed:    time.Unix(lastUsed, 0),
	}, nil
}

func serializeOPAQUECredentials(creds *OPAQUECredentials) ([]byte, error) {
	var buf bytes.Buffer
	
	// Write UserID length and UserID
	userIDBytes := []byte(creds.UserID)
	binary.Write(&buf, binary.BigEndian, uint16(len(userIDBytes)))
	buf.Write(userIDBytes)
	
	// Write RegistrationRecord length and RegistrationRecord
	binary.Write(&buf, binary.BigEndian, uint16(len(creds.RegistrationRecord)))
	buf.Write(creds.RegistrationRecord)
	
	// Write UserPrivateKey length and UserPrivateKey
	binary.Write(&buf, binary.BigEndian, uint16(len(creds.UserPrivateKey)))
	buf.Write(creds.UserPrivateKey)
	
	// Write ServerPublicKey length and ServerPublicKey
	binary.Write(&buf, binary.BigEndian, uint16(len(creds.ServerPublicKey)))
	buf.Write(creds.ServerPublicKey)
	
	return buf.Bytes(), nil
}

func deserializeOPAQUECredentials(data []byte) (*OPAQUECredentials, error) {
	buf := bytes.NewReader(data)
	
	// Read UserID
	var userIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &userIDLen); err != nil {
		return nil, err
	}
	userIDBytes := make([]byte, userIDLen)
	if _, err := io.ReadFull(buf, userIDBytes); err != nil {
		return nil, err
	}
	
	// Read RegistrationRecord
	var regRecordLen uint16
	if err := binary.Read(buf, binary.BigEndian, &regRecordLen); err != nil {
		return nil, err
	}
	regRecord := make([]byte, regRecordLen)
	if _, err := io.ReadFull(buf, regRecord); err != nil {
		return nil, err
	}
	
	// Read UserPrivateKey
	var privKeyLen uint16
	if err := binary.Read(buf, binary.BigEndian, &privKeyLen); err != nil {
		return nil, err
	}
	privKey := make([]byte, privKeyLen)
	if _, err := io.ReadFull(buf, privKey); err != nil {
		return nil, err
	}
	
	// Read ServerPublicKey
	var pubKeyLen uint16
	if err := binary.Read(buf, binary.BigEndian, &pubKeyLen); err != nil {
		return nil, err
	}
	pubKey := make([]byte, pubKeyLen)
	if _, err := io.ReadFull(buf, pubKey); err != nil {
		return nil, err
	}
	
	return &OPAQUECredentials{
		UserID:             string(userIDBytes),
		RegistrationRecord: regRecord,
		UserPrivateKey:     privKey,
		ServerPublicKey:    pubKey,
	}, nil
}

func serializeHardwareAuthInfo(info *HardwareAuthInfo) ([]byte, error) {
	var buf bytes.Buffer
	
	// Write TokenType length and TokenType
	typeBytes := []byte(info.TokenType)
	binary.Write(&buf, binary.BigEndian, uint16(len(typeBytes)))
	buf.Write(typeBytes)
	
	// Write CredentialID length and CredentialID
	binary.Write(&buf, binary.BigEndian, uint16(len(info.CredentialID)))
	buf.Write(info.CredentialID)
	
	// Write PublicKey length and PublicKey
	binary.Write(&buf, binary.BigEndian, uint16(len(info.PublicKey)))
	buf.Write(info.PublicKey)
	
	return buf.Bytes(), nil
}

func deserializeHardwareAuthInfo(data []byte) (*HardwareAuthInfo, error) {
	buf := bytes.NewReader(data)
	
	// Read TokenType
	var typeLen uint16
	if err := binary.Read(buf, binary.BigEndian, &typeLen); err != nil {
		return nil, err
	}
	typeBytes := make([]byte, typeLen)
	if _, err := io.ReadFull(buf, typeBytes); err != nil {
		return nil, err
	}
	
	// Read CredentialID
	var credIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &credIDLen); err != nil {
		return nil, err
	}
	credID := make([]byte, credIDLen)
	if _, err := io.ReadFull(buf, credID); err != nil {
		return nil, err
	}
	
	// Read PublicKey
	var pubKeyLen uint16
	if err := binary.Read(buf, binary.BigEndian, &pubKeyLen); err != nil {
		return nil, err
	}
	pubKey := make([]byte, pubKeyLen)
	if _, err := io.ReadFull(buf, pubKey); err != nil {
		return nil, err
	}
	
	return &HardwareAuthInfo{
		TokenType:    string(typeBytes),
		CredentialID: credID,
		PublicKey:    pubKey,
	}, nil
}