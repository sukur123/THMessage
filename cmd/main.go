package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"thmessage/pkg/auth"
	"thmessage/pkg/crypto"
	"thmessage/pkg/network"
	"thmessage/pkg/storage"
	"thmessage/pkg/ui"
)

func main() {
	fmt.Println("Starting THMessage - Secure Messaging over Tor")
	
	// Initialize storage with zero-knowledge encryption
	store, err := storage.NewSecureStorage()
	if err != nil {
		log.Fatalf("Failed to initialize secure storage: %v", err)
	}
	
	// Initialize cryptographic engine with post-quantum capabilities
	cryptoEngine, err := crypto.NewCryptoEngine(true) // Enable post-quantum algorithms
	if err != nil {
		log.Fatalf("Failed to initialize crypto engine: %v", err)
	}
	
	// Initialize authentication with zero-knowledge protocols
	authManager, err := auth.NewAuthManager(cryptoEngine, store)
	if err != nil {
		log.Fatalf("Failed to initialize authentication: %v", err)
	}
	
	// Initialize network layer with Tor connectivity
	netManager, err := network.NewTorNetworkManager()
	if err != nil {
		log.Fatalf("Failed to initialize Tor network: %v", err)
	}
	
	// Start the messaging service
	service := NewMessagingService(store, cryptoEngine, authManager, netManager)
	if err := service.Start(); err != nil {
		log.Fatalf("Failed to start messaging service: %v", err)
	}
	
	// Initialize UI (terminal-based initially)
	userInterface, err := ui.NewTerminalUI(service)
	if err != nil {
		log.Fatalf("Failed to initialize UI: %v", err)
	}
	
	// Run the UI in the background
	go userInterface.Run()
	
	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	
	// Graceful shutdown
	fmt.Println("\nShutting down THMessage...")
	service.Stop()
	store.Close()
}

// MessagingService coordinates all components of the system
type MessagingService struct {
	storage     *storage.SecureStorage
	crypto      *crypto.CryptoEngine
	auth        *auth.AuthManager
	network     *network.TorNetworkManager
	isRunning   bool
}

// NewMessagingService creates a new messaging service
func NewMessagingService(
	storage *storage.SecureStorage,
	crypto *crypto.CryptoEngine,
	auth *auth.AuthManager,
	network *network.TorNetworkManager,
) *MessagingService {
	return &MessagingService{
		storage:   storage,
		crypto:    crypto,
		auth:      auth,
		network:   network,
		isRunning: false,
	}
}

// Start begins the messaging service operations
func (s *MessagingService) Start() error {
	if s.isRunning {
		return fmt.Errorf("service already running")
	}
	
	// Start the network connection over Tor
	if err := s.network.Connect(); err != nil {
		return fmt.Errorf("failed to establish Tor connection: %w", err)
	}
	
	s.isRunning = true
	return nil
}

// Stop gracefully shuts down the messaging service
func (s *MessagingService) Stop() error {
	if !s.isRunning {
		return nil
	}
	
	// Disconnect from the network
	if err := s.network.Disconnect(); err != nil {
		return fmt.Errorf("error disconnecting from Tor network: %w", err)
	}
	
	s.isRunning = false
	return nil
}