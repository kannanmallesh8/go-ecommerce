package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"net/http"
	"os"
	"time"
)

func GenerateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(2 * time.Minute)
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Expires:  expiration,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	return state
}
func DeleteCookieHandler(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
	//c.String(http.StatusOK, "Cookie has been deleted")
}

func GenerateUserCookie(w http.ResponseWriter, value string) {
	var expiration = time.Now().Add(2 * time.Minute)
	cookie := http.Cookie{
		Name:     "token",
		Value:    value,
		Expires:  expiration,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

}
func GetUserCookie(w http.ResponseWriter) {
	test := http.Cookie{Name: "token"}
	fmt.Println(test.Value)

}
func SetCookieHandler(c *gin.Context, value string) {
	c.SetCookie("token", value, 3600, "/", "localhost", false, true)
	//c.String(http.StatusOK, "Cookie has been set")
}

func Encrypt(plaintext []byte) ([]byte, error) {
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	salt := []byte(encryptionKey)
	iterations := 10000
	keyLength := 32 // 32 bytes for AES-256

	key := pbkdf2.Key([]byte("Mallesh"), salt, iterations, keyLength, sha256.New)

	var (
		c   cipher.Block
		gcm cipher.AEAD
		err error
	)

	c, err = aes.NewCipher(key)

	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	gcm, err = cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext []byte, organizationName string) ([]byte, error) {
	encryptionKey := os.Getenv("ENCRYPTION_KEY")

	// Derive a key from the organization name using PBKDF2
	salt := []byte(encryptionKey)
	iterations := 10000
	keyLength := 32 // 32 bytes for AES-256

	key := pbkdf2.Key([]byte(organizationName), salt, iterations, keyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func EncryptWithOrg(plaintext []byte, orgName string) ([]byte, error) {

	var (
		c   cipher.Block
		gcm cipher.AEAD
		err error
	)

	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	salt := []byte(encryptionKey)
	iterations := 10000
	keyLength := 32 // 32 bytes for AES-256

	key := pbkdf2.Key([]byte(orgName), salt, iterations, keyLength, sha256.New)

	c, err = aes.NewCipher(key)

	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	gcm, err = cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptWithOrganization(ciphertext []byte, orgName string) ([]byte, error) {
	encryptionKey := os.Getenv("ENCRYPTION_KEY")

	// Derive a key from the organization name using PBKDF2
	salt := []byte(encryptionKey)
	iterations := 10000
	keyLength := 32 // 32 bytes for AES-256

	key := pbkdf2.Key([]byte(orgName), salt, iterations, keyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
