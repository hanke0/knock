package main

import (
	_ "embed"
	"log"
	"sync"

	"bytes"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
)

//go:embed index.html
var indexHTML []byte

func getCSRF() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func writeHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Add("Set-Cookie", fmt.Sprintf("csrf-token=%s; Max-Age=3000; Path=/knock; Secure; HttpOnly; SameSite=Strict", getCSRF()))
}

func normalizeIP(ip string) string {
	a := net.ParseIP(ip)
	if a == nil {
		return ""
	}
	if !a.IsGlobalUnicast() {
		return ""
	}
	a = a.To4()
	if a == nil {
		return ""
	}
	return a.String()
}

var nftlist = `
table inet knock-table {
	set addr-set-sshd {
			type ipv4_addr
			elements = { }
	}

	chain knock-table {
			type filter hook input priority filter - 1; policy accept;
			tcp dport { %d } ip saddr @addr-set-sshd reject with icmp port-unreachable
	}
}
`

var nftadd = `
add element inet knock-table addr-set-sshd { %s }
`

var nftdel = `
delete element inet knock-table addr-set-sshd { %s }
`

type Buffer struct {
	b bytes.Buffer
	m sync.Mutex
}

func (b *Buffer) Write(p []byte) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
	return b.b.Write(p)
}

func nftExecf(format string, args ...interface{}) (string, bool) {
	var buf Buffer
	var stdin bytes.Buffer
	fmt.Fprintf(&buf, format, args...)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = &stdin
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(&buf, "\n%v", err)
		return buf.b.String(), false
	}
	return buf.b.String(), true
}

func allowIP(ip string) bool {
	s, ok := nftExecf(nftadd, ip)
	log.Printf("nft delete: %s, success=%v, result: %s", ip, ok, s)
	return ok
}

func disallowIP(ip string) bool {
	s, ok := nftExecf(nftdel, ip)
	log.Printf("nft del: %s, success=%v, result: %s", ip, ok, s)
	return ok
}

func main() {
	envPort := os.Getenv("PORT")
	if envPort == "" {
		envPort = "22"
	}
	port, err := strconv.Atoi(envPort)
	if err != nil {
		panic(err)
	}
	if port < 1 || port > 65535 {
		panic("bad port")
	}
	s, ok := nftExecf(nftlist, port)
	log.Printf("nft list: success=%v, result: %s", ok, s)
	if !ok {
		panic("nft list failed")
	}

	http.HandleFunc("/knock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			writeHeader(w)
			w.Header().Set("Content-Length", strconv.Itoa(len(indexHTML)))
			w.WriteHeader(200)
			w.Write(indexHTML)
			return
		}
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		ip := normalizeIP(r.Header.Get("X-Real-IP"))
		if ip == "" {
			http.Error(w, "Bad IP", http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		token := r.FormValue("csrf-token")
		if token == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		var csrf string
		for _, v := range r.Cookies() {
			if v.Name == "csrf-token" {
				csrf = v.Value
				break
			}
		}
		if csrf == "" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if token != csrf {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		ok := allowIP(ip)
		writeHeader(w)
		w.WriteHeader(200)
		fmt.Fprintf(w, "OK: %v", ok)
	})

	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("Listening on %s\n", addr)
	http.ListenAndServe(addr, nil)
}
