package main

import (
	"compress/gzip"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
)

func main() {
	// Gosec G101: Hardcoded credentials
	// CWE-798: Use of Hard-coded Credentials
	// Vulnerability: Hard-coding credentials in source code is a security risk.
	// If an attacker gains access to the source code, they can easily extract the credentials.
	// Best practice is to store credentials securely, such as in environment variables or a secrets manager.
	const password = "secret123"
	if password == "secret123" {
		fmt.Println("Access granted!")
	}

	// Gosec G501: Blacklisted import crypto/md5
	// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
	// Vulnerability: The MD5 hash function is cryptographically broken and should not be used for security purposes.
	// It is vulnerable to collision attacks, where two different inputs can produce the same hash output.
	// Best practice is to use a secure hash function like SHA-256 or SHA-3.
	hash := md5.New()
	hash.Write([]byte("test"))
	fmt.Printf("%x", hash.Sum(nil))

	// Gosec G304: File path provided as taint input
	// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
	// Vulnerability: Using user-supplied input directly as a file path can lead to path traversal vulnerabilities.
	// An attacker can craft a malicious path to access files outside the intended directory.
	// Best practice is to validate and sanitize user input before using it as a file path.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		filePath := r.URL.Query().Get("path")
		data, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	// Gosec G204: Subprocess launched with variable
	// CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
	// Vulnerability: Executing a command with user-supplied input can lead to command injection vulnerabilities.
	// An attacker can inject malicious commands to gain unauthorized access or perform destructive actions.
	// Best practice is to avoid using user input directly in commands and use safe alternatives like parameterized queries.
	userInput := "ls -l; rm -rf ./" // NOTE: We are not going to erase the whole hard drive; at worst, we will erase the current directory
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()

	// Gosec G104: Errors unhandled
	// Vulnerability: Ignoring errors can lead to unexpected behavior and security vulnerabilities.
	// Unhandled errors may result in resource leaks, inconsistent state, or exposure of sensitive information.
	// Best practice is to properly handle and log errors to ensure the stability and security of the application.
	f, _ := os.Open("file.txt")
	defer f.Close()

	// Gosec G201: SQL query construction using format string
	// CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
	// Vulnerability: Constructing SQL queries by directly concatenating user input can lead to SQL injection vulnerabilities.
	// An attacker can manipulate the input to modify the SQL query and gain unauthorized access to the database.
	// Best practice is to use parameterized queries or prepared statements to separate user input from the SQL query structure.
	username := "admin"
	pass := "' OR 1=1--"
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, pass)
	db, _ := sql.Open("mysql", "user:password@/dbname")
	db.Exec(query)

	// Gosec G401: Use of weak cryptographic primitive
	// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
	// Vulnerability: Using weak cryptographic primitives, such as DES, can compromise the security of encrypted data.
	// These algorithms have known vulnerabilities and are susceptible to attacks.
	// Best practice is to use strong, modern cryptographic algorithms like AES with appropriate key sizes.
	key := []byte("weak-key")
	block, _ := des.NewCipher(key)
	fmt.Printf("%x", block)

	// Gosec G402: TLS MinVersion too low
	// CWE-326: Inadequate Encryption Strength
	// Vulnerability: Using a low TLS version, such as SSL 3.0, can expose the communication to known vulnerabilities.
	// Older TLS versions have weaknesses that can be exploited by attackers to compromise the security of the connection.
	// Best practice is to use a minimum TLS version of 1.2 or higher and disable support for older, insecure versions.
	config := &tls.Config{
		MinVersion: tls.VersionSSL30,
	}
	_, _ = tls.Dial("tcp", "example.com:443", config)

	// Gosec G404: Use of weak random number generator
	// CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
	// Vulnerability: Using a weak random number generator, such as the default math/rand package, can lead to predictable and insecure random values.
	// Attackers may be able to guess or reproduce the generated random numbers, compromising the security of the system.
	// Best practice is to use a cryptographically secure random number generator, such as crypto/rand, for security-sensitive operations.
	token := rand.Int()
	fmt.Println("Random token:", token)

	// Gosec G501: Blacklisted import crypto/rc4
	// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
	// Vulnerability: The RC4 stream cipher is considered weak and should not be used for encryption.
	// It has biases and vulnerabilities that can be exploited to recover the plaintext from the ciphertext.
	// Best practice is to use secure encryption algorithms like AES-GCM or ChaCha20-Poly1305.
	cipher, _ := rc4.NewCipher([]byte("secret"))
	fmt.Printf("%x", cipher)

	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Gosec G107: Potential HTTP request made with variable url
	// CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')
	// Vulnerability: Making an HTTP request with a user-supplied URL can lead to server-side request forgery (SSRF) vulnerabilities.
	// An attacker can manipulate the URL to make requests to internal or external systems, potentially accessing sensitive data or performing unauthorized actions.
	// Best practice is to validate and sanitize the URL input, restrict the allowed domains or schemes, and use a whitelist approach if possible.
	url := resp.Request.URL.Query().Get("url")
	http.Get(url)

	// Gosec G109: Potential Integer overflow made by strconv.Atoi result conversion to int16/32
	// CWE-190: Integer Overflow or Wraparound
	// Vulnerability: Converting a string to an integer without proper bounds checking can lead to integer overflow vulnerabilities.
	// If the input string represents a number that is too large for the target integer type, it can cause unexpected behavior or security issues.
	// Best practice is to use appropriate integer types with sufficient range and perform proper error handling and input validation.
	val := resp.Request.URL.Query().Get("val")
	num, _ := strconv.Atoi(val)
	var intVal int16 = int16(num)
	fmt.Println(intVal)

	// Gosec G110: Potential DoS vulnerability via decompression bomb
	// CWE-409: Improper Handling of Highly Compressed Data (Data Amplification)
	// Vulnerability: Decompressing user-supplied compressed data without proper limits can lead to denial-of-service (DoS) attacks.
	// An attacker can craft a small compressed payload that expands to a extremely large size upon decompression, consuming excessive memory and CPU resources.
	// Best practice is to set appropriate size limits on the decompressed data and handle decompression errors gracefully.
	http.HandleFunc("/decompress", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<30) // 1GB
		gzr, _ := gzip.NewReader(r.Body)
		_, _ = io.Copy(os.Stdout, gzr)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
