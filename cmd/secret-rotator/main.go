package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	infoColor = color.New(color.FgBlue)
	warnColor = color.New(color.FgYellow)
	errorColor = color.New(color.FgRed)
	successColor = color.New(color.FgGreen)
	criticalColor = color.New(color.FgRed, color.Bold)
	noticeColor = color.New(color.FgCyan)
)

// SecretType represents the type of secret
type SecretType string

const (
	SecretTypeAWS        SecretType = "aws"
	SecretTypeVault      SecretType = "vault"
	SecretTypeAzure      SecretType = "azure"
	SecretTypeGCP        SecretType = "gcp"
	SecretTypeDatabase   SecretType = "database"
	SecretTypeAPIKey     SecretType = "apikey"
	SecretTypeCertificate SecretType = "certificate"
	SecretTypeGeneric    SecretType = "generic"
)

// SecretManager defines the interface for secret management
type SecretManager interface {
	RotateSecret(secretID string) (string, error)
	ValidateSecret(secretID, newSecret string) error
	UpdateApplications(secretID, newSecret string) error
	AuditRotation(secretID string) error
}

// Secret represents a secret to be rotated
type Secret struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Type            SecretType   `json:"type"`
	Manager         SecretType   `json:"manager"`
	CurrentSecret   string       `json:"-"` // Not serialized
	Location        string       `json:"location"`
	ApplicationIDs  []string     `json:"application_ids"`
	LastRotated     time.Time    `json:"last_rotated"`
	NextRotation    time.Time    `json:"next_rotation"`
	RotationPolicy  string       `json:"rotation_policy"`
	Status          string       `json:"status"`
}

// RotationConfig holds rotation configuration
type RotationConfig struct {
	Secrets          []Secret   `json:"secrets"`
	DefaultPolicy    string     `json:"default_policy"`
	MaxAgeDays       int        `json:"max_age_days"`
	GracePeriodHours int        `json:"grace_period_hours"`
	AuditEnabled     bool       `json:"audit_enabled"`
	Notifications    NotificationConfig `json:"notifications"`
}

// NotificationConfig holds notification settings
type NotificationConfig struct {
	Email    []string `json:"email"`
	SlackWebhook string `json:"slack_webhook"`
	PagerDuty string `json:"pagerduty"`
}

// RotationResult holds the result of a rotation operation
type RotationResult struct {
	SecretID   string    `json:"secret_id"`
	SecretName string    `json:"secret_name"`
	Status     string    `json:"status"`
	PreviousSecret string `json:"-"`
	NewSecret  string      `json:"-"`
	Error      string      `json:"error,omitempty"`
	RotatedAt  time.Time   `json:"rotated_at"`
}

// SecretRotator handles secret rotation
type SecretRotator struct {
	config       *RotationConfig
	managers     map[SecretType]SecretManager
	results      []RotationResult
	dryRun       bool
	force        bool
	verbose      bool
	failOnErrors bool
}

// NewSecretRotator creates a new SecretRotator
func NewSecretRotator(dryRun, force, verbose, failOnErrors bool) *SecretRotator {
	return &SecretRotator{
		config: &RotationConfig{
			DefaultPolicy: "monthly",
			MaxAgeDays:    90,
			GracePeriodHours: 24,
			AuditEnabled:  true,
			Notifications: NotificationConfig{},
		},
		managers: make(map[SecretType]SecretManager),
		results:  make([]RotationResult, 0),
		dryRun:   dryRun,
		force:    force,
		verbose:  verbose,
		failOnErrors: failOnErrors,
	}
}

// GenerateSecret generates a random secret
func GenerateSecret(length int, secretType SecretType) string {
	switch secretType {
	case SecretTypeAWS:
		// AWS Access Key ID format
		prefix := "AKIA"
		suffix := make([]byte, 16)
		rand.Read(suffix)
		return prefix + hex.EncodeToString(suffix)[:16]
		
	case SecretTypeDatabase:
		// Database password
		charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
		b := make([]byte, length)
		rand.Read(b)
		for i := range b {
			b[i] = charset[int(b[i])%len(charset)]
		}
		return string(b)
		
	case SecretTypeAPIKey:
		// Generic API key
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, length)
		rand.Read(b)
		for i := range b {
			b[i] = charset[int(b[i])%len(charset)]
		}
		return "sk-" + hex.EncodeToString(b)[:32]
		
	case SecretTypeCertificate:
		// Certificate private key (simulated)
		return "-----BEGIN PRIVATE KEY-----\n" + 
			hex.EncodeToString(make([]byte, 64)) + "\n-----END PRIVATE KEY-----"
			
	default:
		// Generic secret
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, length)
		rand.Read(b)
		for i := range b {
			b[i] = charset[int(b[i])%len(charset)]
		}
		return hex.EncodeToString(b)
	}
}

// DetectSecretType detects the type of secret based on its characteristics
func DetectSecretType(secret string, location string) SecretType {
	locLower := strings.ToLower(location)
	
	if strings.HasPrefix(secret, "AKIA") || strings.Contains(locLower, "aws") {
		return SecretTypeAWS
	}
	if strings.HasPrefix(secret, "-----BEGIN") {
		return SecretTypeCertificate
	}
	if strings.HasPrefix(secret, "sk-") || strings.Contains(locLower, "api") {
		return SecretTypeAPIKey
	}
	if strings.Contains(locLower, "database") || strings.Contains(locLower, "db") ||
	   strings.Contains(locLower, "mysql") || strings.Contains(locLower, "postgres") {
		return SecretTypeDatabase
	}
	if strings.Contains(locLower, "vault") || strings.Contains(locLower, "hashicorp") {
		return SecretTypeVault
	}
	if strings.Contains(locLower, "azure") || strings.Contains(locLower, "keyvault") {
		return SecretTypeAzure
	}
	if strings.Contains(locLower, "gcp") || strings.Contains(locLower, "google") {
		return SecretTypeGCP
	}
	
	return SecretTypeGeneric
}

// LoadConfig loads rotation configuration from file
func (sr *SecretRotator) LoadConfig(configPath string) error {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	
	if err := json.Unmarshal(content, sr.config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}
	
	if sr.verbose {
		noticeColor.Printf("✅ Loaded configuration from: %s\n", configPath)
	}
	
	return nil
}

// DiscoverSecrets scans for secrets in the specified paths
func (sr *SecretRotator) DiscoverSecrets(paths []string) error {
	noticeColor.Println("🔍 Discovering secrets...")
	
	for _, path := range paths {
		infoColor.Printf("Scanning: %s\n", path)
		
		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			
			if info.IsDir() {
				if strings.HasPrefix(info.Name(), ".") || info.Name() == "node_modules" || info.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			
			// Check if file might contain secrets
			fileExt := strings.ToLower(filepath.Ext(path))
			supportExtensions := map[string]bool{
				".env": true,
				".yaml": true,
				".yml": true,
				".json": true,
				".tfvars": true,
				".conf": true,
				".config": true,
			}
			
			if !supportExtensions[fileExt] {
				return nil
			}
			
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			
			scanner := bufio.NewScanner(strings.NewReader(string(content)))
			lineNum := 0
			
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				
				// Look for secret patterns
				if sr.isSecretLine(line) {
					secretType := DetectSecretType(line, path)
					
					secret := Secret{
						ID:              fmt.Sprintf("%s-%d-%d", filepath.Base(path), lineNum, time.Now().Unix()),
						Name:            fmt.Sprintf("%s:%d", filepath.Base(path), lineNum),
						Type:            secretType,
						Manager:         sr.detectManager(secretType),
						Location:        path,
						ApplicationIDs:  []string{},
						LastRotated:     time.Time{},
						NextRotation:    time.Now().AddDate(0, 1, 0),
						RotationPolicy:  "on-demand",
						Status:          "discovered",
					}
					
					sr.config.Secrets = append(sr.config.Secrets, secret)
					
					if sr.verbose {
						successColor.Printf("  ✅ Found secret: %s (type: %s)\n", secret.Name, secret.Type)
					} else {
						noticeColor.Printf("  ✅ Found: %s\n", secret.Name)
					}
				}
			}
			
			return nil
		})
		
		if err != nil {
			warnColor.Printf("⚠️  Error scanning %s: %v\n", path, err)
		}
	}
	
	noticeColor.Printf("\n📊 Discovered %d secrets\n\n", len(sr.config.Secrets))
	return nil
}

// isSecretLine checks if a line contains a secret
func (sr *SecretRotator) isSecretLine(line string) bool {
	// Skip comments and empty lines
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || trimmed == "" {
		return false
	}
	
	// Common secret patterns
	secretPatterns := []string{
		"password=",
		"secret=",
		"api_key=",
		"apikey=",
		"access_key=",
		"private_key=",
		"aws_secret=",
		"database_password=",
		"db_password=",
		"connection_string=",
	}
	
	lineLower := strings.ToLower(line)
	
	for _, pattern := range secretPatterns {
		if strings.Contains(lineLower, pattern) {
			return true
		}
	}
	
	return false
}

// detectManager detects the secret manager based on type
func (sr *SecretRotator) detectManager(secretType SecretType) SecretType {
	switch secretType {
	case SecretTypeAWS:
		return SecretTypeAWS
	case SecretTypeCertificate:
		return SecretTypeVault
	case SecretTypeAPIKey:
		return SecretTypeGeneric
	case SecretTypeDatabase:
		return SecretTypeVault
	default:
		return SecretTypeGeneric
	}
}

// RotateSecrets rotates all secrets that need rotation
func (sr *SecretRotator) RotateSecrets() error {
	successColor.Println("🔄 Starting secret rotation...")
	
	for i, secret := range sr.config.Secrets {
		noticeColor.Printf("Rotating secret %d/%d: %s\n", i+1, len(sr.config.Secrets), secret.Name)
		
		// Check if rotation is needed
		if !sr.shouldRotate(secret) {
			if sr.verbose {
				warnColor.Printf("  ⏭️  Skipped: %s (rotation not needed)\n", secret.Name)
			}
			continue
		}
		
		// Perform rotation
		result := sr.rotateSingleSecret(secret)
		sr.results = append(sr.results, result)
		
		// Print progress
		if sr.verbose {
			fmt.Printf("\r📊 Progress: %d/%d", i+1, len(sr.config.Secrets))
		}
	}
	
	if sr.verbose {
		fmt.Println()
	}
	
	return nil
}

// shouldRotate checks if a secret should be rotated
func (sr *SecretRotator) shouldRotate(secret Secret) bool {
	// Force rotation if requested
	if sr.force {
		return true
	}
	
	// Check if never rotated
	if secret.LastRotated.IsZero() {
		return true
	}
	
	// Check rotation policy
	switch secret.RotationPolicy {
	case "monthly":
		return time.Since(secret.NextRotation).Hours() > 0
	case "quarterly":
		return time.Since(secret.NextRotation).Hours() > 0
	case "annually":
		return time.Since(secret.NextRotation).Hours() > 0
	case "on-demand":
		return sr.force
	case "max-age":
		return time.Since(secret.LastRotated).Hours() > float64(sr.config.MaxAgeDays*24)
	default:
		return sr.force
	}
}

// rotateSingleSecret rotates a single secret
func (sr *SecretRotator) rotateSingleSecret(secret Secret) RotationResult {
	result := RotationResult{
		SecretID:   secret.ID,
		SecretName: secret.Name,
		Status:     "pending",
		RotatedAt:  time.Now(),
	}
	
	if sr.dryRun {
		// In dry-run mode, just generate new secret
		newSecret := GenerateSecret(32, secret.Type)
		result.NewSecret = newSecret
		result.Status = "would_rotate"
		
		successColor.Printf("  ✅ Would rotate %s\n", secret.Name)
		if sr.verbose {
			noticeColor.Printf("    New secret (preview): %s...\n", newSecret[:8])
		}
		
		return result
	}
	
	// Generate new secret
	newSecret := GenerateSecret(32, secret.Type)
	result.NewSecret = newSecret
	
	// Update secret manager (in real implementation)
	if err := sr.updateSecretManager(secret, newSecret); err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		errorColor.Printf("  ❌ Failed to rotate %s: %v\n", secret.Name, err)
		return result
	}
	
	// Update applications
	if err := sr.updateApplications(secret, newSecret); err != nil {
		result.Status = "partial"
		result.Error = err.Error()
		warnColor.Printf("  ⚠️  Partial rotation for %s: %v\n", secret.Name, err)
	} else {
		result.Status = "success"
		successColor.Printf("  ✅ Rotated %s\n", secret.Name)
	}
	
	// Audit rotation
	if sr.config.AuditEnabled {
		if err := sr.auditRotation(secret.ID); err != nil {
			warnColor.Printf("  ⚠️  Audit warning for %s: %v\n", secret.Name, err)
		}
	}
	
	// Update next rotation date
	secret.NextRotation = time.Now().AddDate(0, 1, 0)
	
	return result
}

// updateSecretManager updates the secret in the secret manager
func (sr *SecretRotator) updateSecretManager(secret Secret, newSecret string) error {
	// In a real implementation, this would call AWS Secrets Manager, HashiCorp Vault, etc.
	// For now, we just simulate the rotation
	
	// Example AWS Secrets Manager rotation
	// aws-secrets-manager rotate-secret --secret-id <secret-id>
	
	// Example Vault rotation
	// vault kv put secret/<path> <key>=<value>
	
	// Simulate rotation delay
	time.Sleep(100 * time.Millisecond)
	
	return nil
}

// updateApplications updates applications with the new secret
func (sr *SecretRotator) updateApplications(secret Secret, newSecret string) error {
	// In a real implementation, this would:
	// 1. Update Kubernetes secrets
	// 2. Update environment variables
	// 3. Update configuration files
	// 4. Trigger application restarts
	
	// Simulate update
	time.Sleep(50 * time.Millisecond)
	
	return nil
}

// auditRotation audits the rotation operation
func (sr *SecretRotator) auditRotation(secretID string) error {
	// In a real implementation, this would log to:
	// - SIEM system
	// - Audit database
	// - CloudTrail
	// - Custom audit logging
	
	return nil
}

// PrintReport prints the rotation report
func (sr *SecretRotator) PrintReport() {
	infoColor.Println("" + strings.Repeat("=", 80))
	infoColor.Println("📊 SECRET ROTATION REPORT")
	infoColor.Println(strings.Repeat("=", 80))
	
	var successCount, failCount, partialCount, skippedCount int
	var totalSecrets int
	
	for _, result := range sr.results {
		totalSecrets++
		switch result.Status {
		case "success":
			successCount++
		case "failed":
			failCount++
		case "partial":
			partialCount++
		case "would_rotate":
			skippedCount++
		}
	}
	
	noticeColor.Printf("✅ Total secrets discovered: %d\n", len(sr.config.Secrets))
	noticeColor.Printf("✅ Total secrets processed: %d\n", totalSecrets)
	successColor.Printf("✅ Successfully rotated:     %d\n", successCount)
	warnColor.Printf("⚠️  Partially rotated:       %d\n", partialCount)
	errorColor.Printf("❌ Failed to rotate:        %d\n", failCount)
	warnColor.Printf("⏭️  Skipped (no rotation):   %d\n", skippedCount)
	
	infoColor.Println(strings.Repeat("=", 80))
	
	// Detailed results
	if len(sr.results) > 0 {
		infoColor.Println("🔍 DETAILED RESULTS:")
		
		sort.Slice(sr.results, func(i, j int) bool {
			return sr.results[i].SecretName < sr.results[j].SecretName
		})
		
		for _, result := range sr.results {
			statusEmoji := map[string]string{
				"success":    "✅",
				"partial":    "⚠️",
				"failed":     "❌",
				"would_rotate": "📋",
			}
			
			emoji := statusEmoji[result.Status]
			
			if result.Status == "success" || result.Status == "would_rotate" {
				successColor.Printf("%s %s\n", emoji, result.SecretName)
			} else {
				errorColor.Printf("%s %s\n", emoji, result.SecretName)
			}
			
			infoColor.Printf("    ID: %s\n", result.SecretID)
			infoColor.Printf("    Status: %s\n", result.Status)
			infoColor.Printf("    Rotated at: %s\n", result.RotatedAt.Format("2006-01-02 15:04:05"))
			
			if result.Error != "" {
				errorColor.Printf("    Error: %s\n", result.Error)
			}
			
			if result.Status == "would_rotate" && sr.verbose {
				noticeColor.Printf("    New secret preview: %s...\n", result.NewSecret[:8])
			}
			
			infoColor.Println(strings.Repeat("-", 60))
		}
	}
	
	infoColor.Println(strings.Repeat("=", 80))
	
	// Exit with error code if failures
	if sr.failOnErrors && (failCount > 0 || partialCount > 0) {
		errorColor.Printf("\n❌ Rotation FAILED: %d failures, %d partial rotations\n", failCount, partialCount)
		os.Exit(1)
	}
	
	if sr.dryRun {
		warnColor.Println("⚠️  This was a DRY RUN. No secrets were actually rotated.")
	} else {
		successColor.Println("✅ Rotation complete!")
	}
}

func main() {
	// Define flags
	configPath := flag.String("config", "", "Path to rotation configuration file")
	discoverPaths := flag.String("discover", "", "Comma-separated paths to discover secrets")
	dryRun := flag.Bool("dry-run", true, "Preview rotation without making changes")
	force := flag.Bool("force", false, "Force rotation of all secrets")
	verbose := flag.Bool("verbose", false, "Verbose output")
	failOnErrors := flag.Bool("fail-on-errors", true, "Exit with error on failures")
	showHelp := flag.Bool("help", false, "Show help message")
	
	flag.Parse()
	
	if *showHelp {
		flag.Usage()
		return
	}
	
	// Create rotator
	rotator := NewSecretRotator(*dryRun, *force, *verbose, *failOnErrors)
	
	// Load configuration if provided
	if *configPath != "" {
		if err := rotator.LoadConfig(*configPath); err != nil {
			errorColor.Printf("❌ Error loading configuration: %v\n", err)
			os.Exit(1)
		}
	}
	
	// Discover secrets if paths provided
	if *discoverPaths != "" {
		paths := strings.Split(*discoverPaths, ",")
		if err := rotator.DiscoverSecrets(paths); err != nil {
			errorColor.Printf("❌ Error discovering secrets: %v\n", err)
			os.Exit(1)
		}
	}
	
	// Rotate secrets
	if err := rotator.RotateSecrets(); err != nil {
		errorColor.Printf("❌ Error during rotation: %v\n", err)
		os.Exit(1)
	}
	
	// Print report
	rotator.PrintReport()
}