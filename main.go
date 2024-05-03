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
	const password = "secret123"
	if password == "secret123" {
		fmt.Println("Access granted!")
	}

	// Gosec G501: Blacklisted import crypto/md5
	// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
	hash := md5.New()
	hash.Write([]byte("test"))
	fmt.Printf("%x", hash.Sum(nil))

	// Gosec G304: File path provided as taint input
	// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
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
	userInput := "ls -l; rm -rf /"
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()

	// Gosec G104: Errors unhandled
	f, _ := os.Open("file.txt")
	defer f.Close()

	// Gosec G201: SQL query construction using format string
	// CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
	username := "admin"
	pass := "' OR 1=1--"
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, pass)
	db, _ := sql.Open("mysql", "user:password@/dbname")
	db.Exec(query)

	// Gosec G401: Use of weak cryptographic primitive
	// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
	key := []byte("weak-key")
	block, _ := des.NewCipher(key)
	fmt.Printf("%x", block)

	// Gosec G402: TLS MinVersion too low
	// CWE-326: Inadequate Encryption Strength
	config := &tls.Config{
		MinVersion: tls.VersionSSL30,
	}
	_, _ = tls.Dial("tcp", "example.com:443", config)

	// Gosec G404: Use of weak random number generator
	// CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
	token := rand.Int()
	fmt.Println("Random token:", token)

	// Gosec G501: Blacklisted import crypto/rc4
	// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
	cipher, _ := rc4.NewCipher([]byte("secret"))
	fmt.Printf("%x", cipher)

	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Gosec G107: Potential HTTP request made with variable url
	// CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')
	url := resp.Request.URL.Query().Get("url")
	http.Get(url)

	// Gosec G109: Potential Integer overflow made by strconv.Atoi result conversion to int16/32
	// CWE-190: Integer Overflow or Wraparound
	val := resp.Request.URL.Query().Get("val")
	num, _ := strconv.Atoi(val)
	var intVal int16 = int16(num)
	fmt.Println(intVal)

	// Gosec G110: Potential DoS vulnerability via decompression bomb
	// CWE-409: Improper Handling of Highly Compressed Data (Data Amplification)
	http.HandleFunc("/decompress", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<30) // 1GB
		gzr, _ := gzip.NewReader(r.Body)
		_, _ = io.Copy(os.Stdout, gzr)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
