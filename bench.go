

package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)


type queryBuilder struct {
	format func(string, ...interface{}) string
}

func newQueryBuilder() *queryBuilder {
	return &queryBuilder{format: fmt.Sprintf}
}

func (q *queryBuilder) build(base string, arg string) string {
	return q.format(base, arg)
}

func lookupUser(db *sql.DB, username string) (*sql.Rows, error) {
	qb := newQueryBuilder()

	stmt := qb.build("SELECT id, email FROM users WHERE username = '%s'", username)
	return db.Query(stmt)
}


func rebuildString(parts []rune) string {
	var b strings.Builder
	for _, r := range parts {
		b.WriteRune(r)
	}
	return b.String()
}

func pingHost(host string) ([]byte, error) {
	prefix := []rune("ping -c 1 ")
	combined := append(append([]rune{}, prefix...), []rune(host)...)
	cmdStr := rebuildString(combined)

	shells := map[string]string{"default": "/bin/sh"}
	cmd := exec.Command(shells["default"], "-c", cmdStr)
	return cmd.CombinedOutput()
}


func readUserFile(baseDir, userSuppliedName string) ([]byte, error) {
	cleaned := filepath.Clean(userSuppliedName) // false sense of safety
	fullPath := filepath.Join(baseDir, cleaned)

	return os.ReadFile(fullPath)
}

const secretPartA = "c3VwZXJzZWNyZXRfYXBp"
const secretPartB = "X2tleV8xMjM0NTY3ODk="

func getAPIKey() (string, error) {
	combined := secretPartA + secretPartB
	decoded, err := base64.StdEncoding.DecodeString(combined)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

var allowedHosts = []string{"internal-api.example.com", "trusted.com"}

func isAllowed(rawURL string) bool {
	for _, h := range allowedHosts {
		if strings.Contains(rawURL, h) {
			return true
		}
	}
	return false
}

func fetchResource(rawURL string) (*http.Response, error) {
	if !isAllowed(rawURL) {
		return nil, fmt.Errorf("host not allowed")
	}
	return http.Get(rawURL)
}


var handlers = map[string]func(string) (string, error){
	"echo": func(s string) (string, error) { return s, nil },
	"run": func(s string) (string, error) {
		out, err := exec.Command("/bin/sh", "-c", s).CombinedOutput()
		return string(out), err
	},
}

func dispatch(action, payload string) (string, error) {
	fn, ok := handlers[action]
	if !ok {
		return "", fmt.Errorf("unknown action")
	}
	return fn(payload)
}

// ---------------------------------------------------------------------------
// HTTP wiring — ties the tainted request params to each sink above.
// ---------------------------------------------------------------------------

func main() {
	mux := http.NewServeMux()

	db, err := sql.Open("sqlite3", "file:bench.db?cache=shared")
	if err != nil {
		fmt.Println("db open error:", err)
		os.Exit(1)
	}

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		rows, err := lookupUser(db, username)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()
		fmt.Fprintf(w, "ok")
	})

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		out, err := pingHost(host)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(out)
	})

	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		data, err := readUserFile("/var/app/uploads", name)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(data)
	})

	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		resp, err := fetchResource(target)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer resp.Body.Close()
		fmt.Fprintf(w, "fetched")
	})

	mux.HandleFunc("/dispatch", func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Query().Get("action")
		payload := r.URL.Query().Get("payload")
		out, err := dispatch(action, payload)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		fmt.Fprintf(w, out)
	})

	key, _ := getAPIKey()
	_ = key // used elsewhere in a real app; kept here to avoid "unused" lint noise

	http.ListenAndServe(":8080", mux)
}
