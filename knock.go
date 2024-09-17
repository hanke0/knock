package main

import (
	_ "embed"
	"regexp"
	"strings"

	"bytes"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
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

func writeHeader(w http.ResponseWriter, raw bool) {
	if raw {
		w.Header().Set("Content-Type", "text/plain")
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Add("Set-Cookie", fmt.Sprintf("csrf-token=%s; Max-Age=3000; Path=/knock; Secure; SameSite=Strict", getCSRF()))
}

func normalizeIP(ip string) net.IP {
	a := net.ParseIP(ip)
	if a == nil {
		return nil
	}
	if !a.IsGlobalUnicast() {
		return nil
	}
	return a
}

var nftAddIPv4 = `add element inet filter ipv4_ssh_allow_set { %s }`
var nftAddIPv6 = `add element inet filter ipv6_ssh_allow_set { %s }`
var nftBanIPv4 = `add element inet filter ipv4_block_set { %s }`

var nftdel = `
flush set inet filter addr-set-sshd; 
flush set inet filter ipv6-addr-set-sshd;`

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
	fmt.Fprintf(&stdin, format, args...)
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

func allowIP(ip net.IP) bool {
	var (
		s  string
		ok bool
	)
	if v := ip.To4(); len(v) == net.IPv4len {
		s, ok = nftExecf(nftAddIPv4, v.String())
	} else {
		s, ok = nftExecf(nftAddIPv6, ip.String())
	}
	log.Printf("nft delete: %s, success=%v, result: %s", ip, ok, s)
	return ok
}

var globalToken string

func checkToken(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Parse Form Error", http.StatusBadRequest)
		return false
	}

	token := r.FormValue("csrf-token")
	if token == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return false
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
		return false
	}
	if token != csrf {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	token = r.Form.Get("token")
	if token != globalToken {
		http.Error(w, "Bad Token", http.StatusForbidden)
		return false
	}
	return true
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
	if v := os.Getenv("NFTABLES_ENABLE_IPV4_ACTION"); v != "" {
		nftAddIPv4 = v
	}
	if v := os.Getenv("NFTABLES_ENABLE_IPV6_ACTION"); v != "" {
		nftAddIPv6 = v
	}
	if v := os.Getenv("NFTABLES_FLUSH_ACTION"); v != "" {
		nftdel = v
	}
	if v := os.Getenv("NFTABLES_BAN_IPV4_ACTION"); v != "" {
		nftBanIPv4 = v
	}

	log.Printf("nft add ipv4 action: %s", nftAddIPv4)
	log.Printf("nft add ipv6 action: %s", nftAddIPv6)
	log.Printf("nft flush action: %s", nftdel)
	log.Printf("nft ban ipv4 action: %s", nftBanIPv4)
	var ipSplitRE = regexp.MustCompile(`[\s,;]*`)
	http.HandleFunc("/knock/flush", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkToken(w, r) {
			return
		}
		s, ok := nftExecf(nftdel)
		log.Printf("nft flush: success=%v, result: %s", ok, s)
		writeHeader(w, true)
		w.WriteHeader(200)
		fmt.Fprintf(w, "OK: %v", ok)
	})

	http.HandleFunc("/knock/ban", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkToken(w, r) {
			return
		}
		var goods []string
		ips := r.FormValue("ips")
		for _, ip := range ipSplitRE.Split(ips, -1) {
			if v := normalizeIP(ip); v != nil {
				goods = append(goods, v.String())
			}
		}
		if len(goods) == 0 {
			http.Error(w, fmt.Sprintf("Bad IP: %s", ips), http.StatusBadRequest)
			return
		}
		goodIPs := strings.Join(goods, ",")
		s, ok := nftExecf(nftdel, goodIPs)
		log.Printf("nft ban ip: success=%v, result: %s", ok, s)
		writeHeader(w, true)
		w.WriteHeader(200)
		fmt.Fprintf(w, "Input  IP: %s\n", ips)
		fmt.Fprintf(w, "Parsed IP: %s\n", goodIPs)
		fmt.Fprintf(w, "OK: %v", ok)
	})

	http.HandleFunc("/knock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			writeHeader(w, false)
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
		if ip == nil {
			http.Error(w, "Bad IP", http.StatusBadRequest)
			return
		}
		if !checkToken(w, r) {
			return
		}

		ok := allowIP(ip)
		writeHeader(w, true)
		w.WriteHeader(200)
		fmt.Fprintln(w, ip)
		fmt.Fprintf(w, "OK: %v", ok)
	})

	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	globalToken = os.Getenv("TOKEN")
	if globalToken == "" {
		globalToken = getCSRF()
		log.Printf("Generated token: %s", globalToken)
	}
	log.Printf("Listening on %s\n", addr)
	http.ListenAndServe(addr, nil)
}
