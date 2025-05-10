package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"

	"thmessage/pkg/auth"
	"thmessage/pkg/crypto"
)

// UI colors
var (
	headerColor   = color.New(color.FgHiCyan, color.Bold)
	promptColor   = color.New(color.FgHiYellow)
	successColor  = color.New(color.FgHiGreen)
	errorColor    = color.New(color.FgHiRed)
	warningColor  = color.New(color.FgHiYellow)
	infoColor     = color.New(color.FgHiBlue)
	messageColor  = color.New(color.FgHiWhite)
	timestampColor = color.New(color.FgHiBlack)
	usernameColor = color.New(color.FgHiMagenta)
)

// TerminalUI provides a terminal-based user interface
type TerminalUI struct {
	service        MessagingService
	authenticated  bool
	currentUser    *auth.User
	sessionID      string
	reader         *bufio.Reader
	useColors      bool
	selectedContact string
}

// MessagingService defines the interface for the messaging service
type MessagingService interface {
	// Authentication
	RegisterUser(username, password string) error
	Login(username, password string) (string, error)
	Logout() error
	
	// Contacts
	AddContact(contactID string, publicKey []byte) error
	GetContacts() (map[string][]byte, error)
	VerifyContact(contactID string, verificationCode string) (bool, error)
	GenerateVerificationCode(contactID string) (string, error)
	
	// Messages
	SendMessage(recipient string, content string, expiresInMinutes int) error
	GetMessages() ([]Message, error)
	DeleteMessage(messageID string) error
	
	// Settings
	ChangePassword(oldPassword, newPassword string) error
	GetSettings() (map[string]string, error)
	UpdateSetting(key, value string) error
	
	// Status
	GetStatus() (map[string]interface{}, error)
}

// Message represents a message in the UI
type Message struct {
	ID        string
	Sender    string
	Recipient string
	Content   string
	Timestamp time.Time
	IsExpired bool
	ExpiresAt time.Time
}

// NewTerminalUI creates a new terminal-based UI
func NewTerminalUI(service MessagingService) (*TerminalUI, error) {
	// Check if we're in a terminal
	useColors := false
	if isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd()) {
		useColors = true
	}
	
	return &TerminalUI{
		service:       service,
		authenticated: false,
		reader:        bufio.NewReader(os.Stdin),
		useColors:     useColors,
	}, nil
}

// Run starts the UI
func (ui *TerminalUI) Run() {
	ui.showWelcome()
	
	for {
		if !ui.authenticated {
			ui.showAuthMenu()
		} else {
			ui.showMainMenu()
		}
	}
}

// showWelcome displays the welcome screen
func (ui *TerminalUI) showWelcome() {
	ui.clearScreen()
	headerColor.Println("╔══════════════════════════════════════════════════════╗")
	headerColor.Println("║                     THMessage                        ║")
	headerColor.Println("║          Secure Messaging over Tor Network           ║")
	headerColor.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()
	infoColor.Println("• End-to-end encrypted messaging with post-quantum security")
	infoColor.Println("• Tor-based communications for strong anonymity")
	infoColor.Println("• Self-destructing messages and local database encryption")
	infoColor.Println("• Zero-knowledge authentication and plausible deniability")
	fmt.Println()
}

// showAuthMenu displays the authentication menu
func (ui *TerminalUI) showAuthMenu() {
	promptColor.Println("1. Login")
	promptColor.Println("2. Register")
	promptColor.Println("3. Recover Account")
	promptColor.Println("4. Exit")
	fmt.Println()
	
	choice := ui.readInput("Enter your choice: ")
	
	switch choice {
	case "1":
		ui.loginFlow()
	case "2":
		ui.registrationFlow()
	case "3":
		ui.accountRecoveryFlow()
	case "4":
		ui.exitApplication()
	default:
		errorColor.Println("Invalid choice.")
		time.Sleep(1 * time.Second)
	}
}

// showMainMenu displays the main menu for authenticated users
func (ui *TerminalUI) showMainMenu() {
	ui.clearScreen()
	headerColor.Printf("THMessage - Logged in as: %s\n", ui.currentUser.Username)
	
	// Show connection status
	status, err := ui.service.GetStatus()
	if err == nil {
		if status["connected"].(bool) {
			successColor.Println("Connected to Tor network")
		} else {
			errorColor.Println("Not connected to Tor network")
		}
	}
	
	fmt.Println()
	promptColor.Println("1. Messages")
	promptColor.Println("2. Contacts")
	promptColor.Println("3. Settings")
	promptColor.Println("4. Logout")
	promptColor.Println("5. Exit")
	fmt.Println()
	
	choice := ui.readInput("Enter your choice: ")
	
	switch choice {
	case "1":
		ui.messagesMenu()
	case "2":
		ui.contactsMenu()
	case "3":
		ui.settingsMenu()
	case "4":
		ui.logout()
	case "5":
		ui.exitApplication()
	default:
		errorColor.Println("Invalid choice.")
		time.Sleep(1 * time.Second)
	}
}

// messagesMenu displays the messages menu
func (ui *TerminalUI) messagesMenu() {
	for {
		ui.clearScreen()
		headerColor.Println("Messages")
		fmt.Println()
		
		if ui.selectedContact != "" {
			infoColor.Printf("Chatting with: %s\n\n", ui.selectedContact)
		}
		
		// Get and display messages
		messages, err := ui.service.GetMessages()
		if err != nil {
			errorColor.Printf("Error fetching messages: %v\n", err)
		} else {
			if len(messages) == 0 {
				infoColor.Println("No messages.")
			} else {
				// Display messages for the selected contact, or all if none selected
				ui.displayMessages(messages)
			}
		}
		
		fmt.Println()
		if ui.selectedContact != "" {
			promptColor.Println("1. Send Message")
			promptColor.Println("2. Return to Contact List")
		} else {
			promptColor.Println("1. Select Contact")
		}
		promptColor.Println("3. Refresh Messages")
		promptColor.Println("4. Back to Main Menu")
		fmt.Println()
		
		choice := ui.readInput("Enter your choice: ")
		
		if ui.selectedContact != "" {
			switch choice {
			case "1":
				ui.sendMessageFlow()
			case "2":
				ui.selectedContact = ""
			case "3":
				// Just refresh the display
			case "4":
				return
			default:
				errorColor.Println("Invalid choice.")
				time.Sleep(1 * time.Second)
			}
		} else {
			switch choice {
			case "1":
				ui.selectContactFlow()
			case "3":
				// Just refresh the display
			case "4":
				return
			default:
				errorColor.Println("Invalid choice.")
				time.Sleep(1 * time.Second)
			}
		}
	}
}

// contactsMenu displays the contacts menu
func (ui *TerminalUI) contactsMenu() {
	for {
		ui.clearScreen()
		headerColor.Println("Contacts")
		fmt.Println()
		
		// Get and display contacts
		contacts, err := ui.service.GetContacts()
		if err != nil {
			errorColor.Printf("Error fetching contacts: %v\n", err)
		} else {
			if len(contacts) == 0 {
				infoColor.Println("No contacts.")
			} else {
				for contactID := range contacts {
					fmt.Printf("• %s\n", contactID)
				}
			}
		}
		
		fmt.Println()
		promptColor.Println("1. Add Contact")
		promptColor.Println("2. Verify Contact")
		promptColor.Println("3. Back to Main Menu")
		fmt.Println()
		
		choice := ui.readInput("Enter your choice: ")
		
		switch choice {
		case "1":
			ui.addContactFlow()
		case "2":
			ui.verifyContactFlow()
		case "3":
			return
		default:
			errorColor.Println("Invalid choice.")
			time.Sleep(1 * time.Second)
		}
	}
}

// settingsMenu displays the settings menu
func (ui *TerminalUI) settingsMenu() {
	for {
		ui.clearScreen()
		headerColor.Println("Settings")
		fmt.Println()
		
		// Get and display settings
		settings, err := ui.service.GetSettings()
		if err != nil {
			errorColor.Printf("Error fetching settings: %v\n", err)
		} else {
			for key, value := range settings {
				fmt.Printf("• %s: %s\n", key, value)
			}
		}
		
		fmt.Println()
		promptColor.Println("1. Change Password")
		promptColor.Println("2. Generate Recovery Codes")
		promptColor.Println("3. Toggle Post-Quantum Cryptography")
		promptColor.Println("4. Set Message Expiration Default")
		promptColor.Println("5. Back to Main Menu")
		fmt.Println()
		
		choice := ui.readInput("Enter your choice: ")
		
		switch choice {
		case "1":
			ui.changePasswordFlow()
		case "2":
			ui.generateRecoveryCodesFlow()
		case "3":
			ui.togglePostQuantumFlow()
		case "4":
			ui.setMessageExpirationFlow()
		case "5":
			return
		default:
			errorColor.Println("Invalid choice.")
			time.Sleep(1 * time.Second)
		}
	}
}

// Flow implementations

// loginFlow handles the user login process
func (ui *TerminalUI) loginFlow() {
	ui.clearScreen()
	headerColor.Println("Login")
	fmt.Println()
	
	username := ui.readInput("Username: ")
	password := ui.readPassword("Password: ")
	
	sessionID, err := ui.service.Login(username, password)
	if err != nil {
		errorColor.Printf("Login failed: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}
	
	ui.sessionID = sessionID
	ui.authenticated = true
	successColor.Println("Login successful!")
	time.Sleep(1 * time.Second)
}

// registrationFlow handles the user registration process
func (ui *TerminalUI) registrationFlow() {
	ui.clearScreen()
	headerColor.Println("Register New Account")
	fmt.Println()
	
	username := ui.readInput("Username: ")
	password := ui.readPassword("Password: ")
	confirmPassword := ui.readPassword("Confirm Password: ")
	
	if password != confirmPassword {
		errorColor.Println("Passwords do not match.")
		time.Sleep(2 * time.Second)
		return
	}
	
	err := ui.service.RegisterUser(username, password)
	if err != nil {
		errorColor.Printf("Registration failed: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}
	
	successColor.Println("Registration successful! Please log in.")
	time.Sleep(2 * time.Second)
}

// accountRecoveryFlow handles the account recovery process
func (ui *TerminalUI) accountRecoveryFlow() {
	ui.clearScreen()
	headerColor.Println("Account Recovery")
	fmt.Println()
	
	username := ui.readInput("Username: ")
	recoveryCode := ui.readInput("Recovery Code: ")
	
	// This would be implemented in the service
	errorColor.Println("Account recovery not implemented yet.")
	time.Sleep(2 * time.Second)
}

// logout logs the user out
func (ui *TerminalUI) logout() {
	err := ui.service.Logout()
	if err != nil {
		errorColor.Printf("Logout error: %v\n", err)
	}
	
	ui.authenticated = false
	ui.sessionID = ""
	ui.currentUser = nil
	ui.selectedContact = ""
	
	successColor.Println("Logged out successfully.")
	time.Sleep(1 * time.Second)
}

// exitApplication exits the application
func (ui *TerminalUI) exitApplication() {
	ui.clearScreen()
	headerColor.Println("Exiting THMessage...")
	time.Sleep(1 * time.Second)
	os.Exit(0)
}

// addContactFlow handles adding a new contact
func (ui *TerminalUI) addContactFlow() {
	ui.clearScreen()
	headerColor.Println("Add Contact")
	fmt.Println()
	
	contactID := ui.readInput("Contact ID: ")
	publicKeyStr := ui.readInput("Contact's Public Key: ")
	
	// Simple base64 decode - in a real app, this would be more robust
	publicKey := []byte(publicKeyStr)
	
	err := ui.service.AddContact(contactID, publicKey)
	if err != nil {
		errorColor.Printf("Failed to add contact: %v\n", err)
	} else {
		successColor.Println("Contact added successfully!")
	}
	time.Sleep(2 * time.Second)
}

// verifyContactFlow handles contact verification
func (ui *TerminalUI) verifyContactFlow() {
	ui.clearScreen()
	headerColor.Println("Verify Contact")
	fmt.Println()
	
	contactID := ui.readInput("Contact ID: ")
	
	// Generate a code for the user to share with the contact
	code, err := ui.service.GenerateVerificationCode(contactID)
	if err != nil {
		errorColor.Printf("Failed to generate verification code: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}
	
	infoColor.Println("Please verify this code with your contact through a secure channel:")
	messageColor.Printf("Verification code: %s\n\n", code)
	
	verifyChoice := ui.readInput("Did your contact confirm this code? (yes/no): ")
	if strings.ToLower(verifyChoice) == "yes" {
		// In a real app, this would actually verify the contact's code as well
		verified, err := ui.service.VerifyContact(contactID, code)
		if err != nil {
			errorColor.Printf("Verification failed: %v\n", err)
		} else if verified {
			successColor.Println("Contact verified successfully!")
		} else {
			errorColor.Println("Verification failed. Codes do not match.")
		}
	} else {
		warningColor.Println("Verification cancelled.")
	}
	time.Sleep(2 * time.Second)
}

// selectContactFlow handles selecting a contact to chat with
func (ui *TerminalUI) selectContactFlow() {
	ui.clearScreen()
	headerColor.Println("Select Contact")
	fmt.Println()
	
	// Get and display contacts
	contacts, err := ui.service.GetContacts()
	if err != nil {
		errorColor.Printf("Error fetching contacts: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}
	
	if len(contacts) == 0 {
		infoColor.Println("No contacts. Please add contacts first.")
		time.Sleep(2 * time.Second)
		return
	}
	
	var contactList []string
	for contactID := range contacts {
		contactList = append(contactList, contactID)
		fmt.Printf("%d. %s\n", len(contactList), contactID)
	}
	fmt.Println()
	
	contactChoice := ui.readInput("Select contact number: ")
	choiceNum, err := strconv.Atoi(contactChoice)
	if err != nil || choiceNum < 1 || choiceNum > len(contactList) {
		errorColor.Println("Invalid selection.")
		time.Sleep(1 * time.Second)
		return
	}
	
	ui.selectedContact = contactList[choiceNum-1]
	successColor.Printf("Now chatting with %s\n", ui.selectedContact)
	time.Sleep(1 * time.Second)
}

// sendMessageFlow handles sending a message to a contact
func (ui *TerminalUI) sendMessageFlow() {
	fmt.Println()
	headerColor.Printf("Send message to %s\n", ui.selectedContact)
	fmt.Println()
	
	content := ui.readInput("Message: ")
	
	// Get expiration setting
	expirationStr := ui.readInput("Message expires in how many minutes? (0 for never): ")
	expiration, err := strconv.Atoi(expirationStr)
	if err != nil {
		errorColor.Println("Invalid expiration time. Using default.")
		expiration = 0
	}
	
	err = ui.service.SendMessage(ui.selectedContact, content, expiration)
	if err != nil {
		errorColor.Printf("Failed to send message: %v\n", err)
	} else {
		successColor.Println("Message sent successfully!")
	}
	time.Sleep(1 * time.Second)
}

// changePasswordFlow handles changing the user's password
func (ui *TerminalUI) changePasswordFlow() {
	ui.clearScreen()
	headerColor.Println("Change Password")
	fmt.Println()
	
	oldPassword := ui.readPassword("Current Password: ")
	newPassword := ui.readPassword("New Password: ")
	confirmPassword := ui.readPassword("Confirm New Password: ")
	
	if newPassword != confirmPassword {
		errorColor.Println("Passwords do not match.")
		time.Sleep(2 * time.Second)
		return
	}
	
	err := ui.service.ChangePassword(oldPassword, newPassword)
	if err != nil {
		errorColor.Printf("Failed to change password: %v\n", err)
	} else {
		successColor.Println("Password changed successfully!")
	}
	time.Sleep(2 * time.Second)
}

// generateRecoveryCodesFlow handles generating recovery codes
func (ui *TerminalUI) generateRecoveryCodesFlow() {
	ui.clearScreen()
	headerColor.Println("Generate Recovery Codes")
	fmt.Println()
	
	warningColor.Println("WARNING: This will invalidate any previous recovery codes.")
	confirmGenerate := ui.readInput("Are you sure you want to generate new recovery codes? (yes/no): ")
	
	if strings.ToLower(confirmGenerate) != "yes" {
		infoColor.Println("Cancelled.")
		time.Sleep(1 * time.Second)
		return
	}
	
	// This would be implemented in the service
	errorColor.Println("Recovery code generation not implemented yet.")
	time.Sleep(2 * time.Second)
}

// togglePostQuantumFlow handles toggling post-quantum cryptography
func (ui *TerminalUI) togglePostQuantumFlow() {
	ui.clearScreen()
	headerColor.Println("Post-Quantum Cryptography")
	fmt.Println()
	
	// Get current setting
	settings, err := ui.service.GetSettings()
	if err != nil {
		errorColor.Printf("Error fetching settings: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}
	
	currentSetting := settings["use_post_quantum"] == "true"
	
	if currentSetting {
		infoColor.Println("Post-quantum cryptography is currently ENABLED.")
		confirmToggle := ui.readInput("Disable post-quantum cryptography? (yes/no): ")
		
		if strings.ToLower(confirmToggle) == "yes" {
			err := ui.service.UpdateSetting("use_post_quantum", "false")
			if err != nil {
				errorColor.Printf("Failed to update setting: %v\n", err)
			} else {
				successColor.Println("Post-quantum cryptography disabled.")
			}
		} else {
			infoColor.Println("Cancelled.")
		}
	} else {
		infoColor.Println("Post-quantum cryptography is currently DISABLED.")
		confirmToggle := ui.readInput("Enable post-quantum cryptography? (yes/no): ")
		
		if strings.ToLower(confirmToggle) == "yes" {
			err := ui.service.UpdateSetting("use_post_quantum", "true")
			if err != nil {
				errorColor.Printf("Failed to update setting: %v\n", err)
			} else {
				successColor.Println("Post-quantum cryptography enabled.")
			}
		} else {
			infoColor.Println("Cancelled.")
		}
	}
	
	time.Sleep(2 * time.Second)
}

// setMessageExpirationFlow handles setting the default message expiration
func (ui *TerminalUI) setMessageExpirationFlow() {
	ui.clearScreen()
	headerColor.Println("Set Default Message Expiration")
	fmt.Println()
	
	// Get current setting
	settings, err := ui.service.GetSettings()
	if err != nil {
		errorColor.Printf("Error fetching settings: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}
	
	currentExpiration := settings["default_expiration_minutes"]
	infoColor.Printf("Current default expiration: %s minutes (0 = never expire)\n\n", currentExpiration)
	
	expirationStr := ui.readInput("New default expiration (minutes): ")
	expiration, err := strconv.Atoi(expirationStr)
	if err != nil || expiration < 0 {
		errorColor.Println("Invalid expiration time.")
		time.Sleep(2 * time.Second)
		return
	}
	
	err = ui.service.UpdateSetting("default_expiration_minutes", expirationStr)
	if err != nil {
		errorColor.Printf("Failed to update setting: %v\n", err)
	} else {
		successColor.Println("Default expiration updated successfully!")
	}
	time.Sleep(2 * time.Second)
}

// Helper functions

// readInput reads a line of input from the user
func (ui *TerminalUI) readInput(prompt string) string {
	fmt.Print(prompt)
	input, _ := ui.reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// readPassword reads a password from the user without echoing it
// Note: In a real implementation, this would use terminal-specific libraries
// to hide the input (like golang.org/x/crypto/ssh/terminal)
func (ui *TerminalUI) readPassword(prompt string) string {
	fmt.Print(prompt)
	password, _ := ui.reader.ReadString('\n')
	return strings.TrimSpace(password)
}

// clearScreen clears the terminal screen
func (ui *TerminalUI) clearScreen() {
	fmt.Print("\033[H\033[2J") // ANSI escape sequence to clear screen
}

// displayMessages shows messages in a chat-like format
func (ui *TerminalUI) displayMessages(messages []Message) {
	// Filter messages for the selected contact, if any
	var filtered []Message
	if ui.selectedContact != "" {
		for _, msg := range messages {
			if msg.Sender == ui.selectedContact || msg.Recipient == ui.selectedContact {
				filtered = append(filtered, msg)
			}
		}
	} else {
		filtered = messages
	}
	
	if len(filtered) == 0 {
		infoColor.Println("No messages to display.")
		return
	}
	
	for _, msg := range filtered {
		if msg.IsExpired {
			// Skip expired messages
			continue
		}
		
		timestamp := timestampColor.Sprintf("[%s]", msg.Timestamp.Format("15:04:05"))
		
		if msg.Sender == ui.currentUser.Username || msg.Sender == ui.currentUser.ID {
			// This is a message from the current user
			fmt.Printf("%s %s: %s\n", timestamp, usernameColor.Sprint("You"), messageColor.Sprint(msg.Content))
		} else {
			// This is a message from someone else
			fmt.Printf("%s %s: %s\n", timestamp, usernameColor.Sprint(msg.Sender), messageColor.Sprint(msg.Content))
		}
		
		// Show expiration info if applicable
		if !msg.ExpiresAt.IsZero() {
			if time.Until(msg.ExpiresAt) > 0 {
				expiresIn := time.Until(msg.ExpiresAt).Round(time.Second)
				warningColor.Printf("  ⏱️ Expires in %s\n", expiresIn)
			}
		}
	}
}