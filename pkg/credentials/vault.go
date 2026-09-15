package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

var (
	defaultManager     *CredentialManager
	defaultManagerOnce sync.Once
)

// GetManager returns the shared credential manager
func GetManager() *CredentialManager {
	defaultManagerOnce.Do(func() {
		defaultManager = &CredentialManager{
			filePath: getVaultPath(),
			items:    make(map[string]CredentialEntry),
		}
	})
	return defaultManager
}

// CredentialManager manages encrypted credential storage
type CredentialManager struct {
	mu       sync.RWMutex
	filePath string
	salt     []byte
	key      []byte
	items    map[string]CredentialEntry
	loaded   bool
}

// CredentialEntry represents an encrypted credential
type CredentialEntry struct {
	ID        string            `json:"id"`
	Provider  string            `json:"provider"`
	Name      string            `json:"name"`
	Region    string            `json:"region"`
	Data      map[string]string `json:"data"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type storedEntry struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Name      string    `json:"name"`
	Region    string    `json:"region"`
	Data      string    `json:"data"`
	Nonce     string    `json:"nonce"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	HMAC      string    `json:"hmac"`
}

type vaultData struct {
	Version   int           `json:"version"`
	Salt      string        `json:"salt"`
	CreatedAt time.Time     `json:"created_at"`
	Entries   []storedEntry `json:"entries"`
	VaultHMAC string        `json:"vault_hmac"`
}

const (
	vaultVersion = 1
	keyLength    = 32
	saltLength   = 32
	nonceLength  = 12
)

// getVaultPath returns the vault file path
func getVaultPath() string {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	dir := filepath.Join(home, ".hermes", "credentials")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "vault.enc")
}

// deriveKey derives an encryption key from passphrase using Argon2id
func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 64)
}

// load reads and decrypts the vault from disk
func (v *CredentialManager) load() error {
	data, err := os.ReadFile(v.filePath)
	if err != nil {
		return fmt.Errorf("failed to read vault file: %w", err)
	}

	var vault vaultData
	if err := json.Unmarshal(data, &vault); err != nil {
		return fmt.Errorf("failed to parse vault: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(vault.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}
	v.salt = salt

	passphrase := os.Getenv("HARPA_VAULT_PASS")
	if passphrase == "" {
		passphrase = "harpia-default-secure-pass-2024"
	}
	derived := deriveKey(passphrase, v.salt)
	v.key = derived[:keyLength]

	vaultCheck := struct {
		Version   int           `json:"version"`
		Salt      string        `json:"salt"`
		CreatedAt time.Time     `json:"created_at"`
		Entries   []storedEntry `json:"entries"`
	}{vault.Version, vault.Salt, vault.CreatedAt, vault.Entries}

	vaultJSON, _ := json.Marshal(vaultCheck)
	h := hmac.New(sha256.New, v.key)
	h.Write(vaultJSON)
	expectedHMAC := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(expectedHMAC), []byte(vault.VaultHMAC)) {
		v.key = nil
		return errors.New("invalid passphrase")
	}

	for _, entry := range vault.Entries {
		decrypted, err := v.decryptEntry(entry)
		if err != nil {
			v.key = nil
			return fmt.Errorf("failed to decrypt entry %s: %w", entry.ID, err)
		}
		v.items[decrypted.ID] = decrypted
	}

	v.loaded = true
	return nil
}

// save encrypts and writes the vault to disk
func (v *CredentialManager) save() error {
	if v.key == nil {
		return errors.New("vault not unlocked")
	}

	var entries []storedEntry
	for _, item := range v.items {
		encrypted, err := v.encryptEntry(item)
		if err != nil {
			return fmt.Errorf("failed to encrypt entry %s: %w", item.ID, err)
		}
		entries = append(entries, encrypted)
	}

	saltB64 := base64.StdEncoding.EncodeToString(v.salt)
	vault := vaultData{
		Version:   vaultVersion,
		Salt:      saltB64,
		CreatedAt: time.Now(),
		Entries:   entries,
	}

	vaultCheck := struct {
		Version   int           `json:"version"`
		Salt      string        `json:"salt"`
		CreatedAt time.Time     `json:"created_at"`
		Entries   []storedEntry `json:"entries"`
	}{vault.Version, vault.Salt, vault.CreatedAt, vault.Entries}

	vaultJSON, _ := json.Marshal(vaultCheck)
	h := hmac.New(sha256.New, v.key)
	h.Write(vaultJSON)
	vault.VaultHMAC = base64.StdEncoding.EncodeToString(h.Sum(nil))

	data, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vault: %w", err)
	}

	tmpFile := v.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write vault file: %w", err)
	}

	if err := os.Rename(tmpFile, v.filePath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to save vault: %w", err)
	}

	return nil
}

// encryptEntry encrypts a credential entry
func (v *CredentialManager) encryptEntry(entry CredentialEntry) (storedEntry, error) {
	dataJSON, err := json.Marshal(entry.Data)
	if err != nil {
		return storedEntry{}, fmt.Errorf("failed to marshal data: %w", err)
	}

	nonce := make([]byte, nonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return storedEntry{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	block, err := aes.NewCipher(v.key)
	if err != nil {
		return storedEntry{}, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return storedEntry{}, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, dataJSON, nil)

	h := hmac.New(sha256.New, v.key)
	h.Write(ciphertext)
	entryHMAC := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return storedEntry{
		ID:        entry.ID,
		Provider:  entry.Provider,
		Name:      entry.Name,
		Region:    entry.Region,
		Data:      base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		CreatedAt: entry.CreatedAt,
		UpdatedAt: entry.UpdatedAt,
		HMAC:      entryHMAC,
	}, nil
}

// decryptEntry decrypts a credential entry
func (v *CredentialManager) decryptEntry(entry storedEntry) (CredentialEntry, error) {
	nonce, err := base64.StdEncoding.DecodeString(entry.Nonce)
	if err != nil {
		return CredentialEntry{}, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(entry.Data)
	if err != nil {
		return CredentialEntry{}, fmt.Errorf("failed to decode data: %w", err)
	}

	h := hmac.New(sha256.New, v.key)
	h.Write(ciphertext)
	expectedHMAC := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(expectedHMAC), []byte(entry.HMAC)) {
		return CredentialEntry{}, errors.New("entry integrity check failed")
	}

	block, err := aes.NewCipher(v.key)
	if err != nil {
		return CredentialEntry{}, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return CredentialEntry{}, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return CredentialEntry{}, fmt.Errorf("failed to decrypt: %w", err)
	}

	var data map[string]string
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return CredentialEntry{}, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return CredentialEntry{
		ID:        entry.ID,
		Provider:  entry.Provider,
		Name:      entry.Name,
		Region:    entry.Region,
		Data:      data,
		CreatedAt: entry.CreatedAt,
		UpdatedAt: entry.UpdatedAt,
	}, nil
}

// Add stores a new credential
func (v *CredentialManager) Add(entry CredentialEntry) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.key == nil {
		return errors.New("vault not unlocked")
	}

	if entry.ID == "" {
		entry.ID = generateID()
	}

	entry.CreatedAt = time.Now()
	entry.UpdatedAt = time.Now()

	v.items[entry.ID] = entry
	return v.save()
}

// Get retrieves a credential by ID
func (v *CredentialManager) Get(id string) (CredentialEntry, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	entry, ok := v.items[id]
	if !ok {
		return CredentialEntry{}, fmt.Errorf("credential not found: %s", id)
	}

	return entry, nil
}

// GetByProvider retrieves all credentials for a provider
func (v *CredentialManager) GetByProvider(provider string) []CredentialEntry {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var result []CredentialEntry
	for _, entry := range v.items {
		if entry.Provider == provider {
			result = append(result, entry)
		}
	}

	return result
}

// List returns all credentials (without sensitive data)
func (v *CredentialManager) List() []CredentialSummary {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var result []CredentialSummary
	for _, entry := range v.items {
		result = append(result, CredentialSummary{
			ID:        entry.ID,
			Provider:  entry.Provider,
			Name:      entry.Name,
			Region:    entry.Region,
			CreatedAt: entry.CreatedAt,
		})
	}

	return result
}

// Delete removes a credential
func (v *CredentialManager) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.key == nil {
		return errors.New("vault not unlocked")
	}

	delete(v.items, id)
	return v.save()
}

// Unlock unlocks the vault with the given passphrase
func (v *CredentialManager) Unlock(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.key != nil {
		return errors.New("vault already unlocked")
	}

	if v.salt == nil {
		v.salt = make([]byte, saltLength)
		if _, err := io.ReadFull(rand.Reader, v.salt); err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	derived := deriveKey(passphrase, v.salt)
	v.key = derived[:keyLength]

	if _, err := os.Stat(v.filePath); err == nil {
		if err := v.load(); err != nil {
			v.key = nil
			return err
		}
	}

	v.loaded = true
	return nil
}

// Lock locks the vault and clears sensitive data from memory
func (v *CredentialManager) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.key != nil {
		for i := range v.key {
			v.key[i] = 0
		}
		v.key = nil
	}

	for id, item := range v.items {
		for k := range item.Data {
			item.Data[k] = ""
		}
		delete(v.items, id)
	}

	v.loaded = false
}

// IsUnlocked returns whether the vault is unlocked
func (v *CredentialManager) IsUnlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.key != nil
}

// CredentialSummary is a non-sensitive credential summary
type CredentialSummary struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Name      string    `json:"name"`
	Region    string    `json:"region"`
	CreatedAt time.Time `json:"created_at"`
}

// generateID generates a random ID
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
