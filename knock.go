package main

import (
	// embed index.html
	_ "embed"

	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed index.html
var indexHTML string

var indexTemplate *template.Template

func init() {
	var err error
	indexTemplate, err = template.New("index").Parse(indexHTML)
	if err != nil {
		log.Fatalf("error parsing index template: %v", err)
	}
}

func getCSRF() (string, error) {
	ts := time.Now().Unix()
	csrf := strconv.FormatInt(ts, 10)
	return EncryptString([]byte(csrf), globalTokenSha[:])
}

func isGoodCSRF(token string) error {
	plain, err := DecryptString(token, globalTokenSha[:])
	if err != nil {
		return err
	}
	ts, err := strconv.ParseInt(plain, 10, 64)
	if err != nil {
		return err
	}
	t := time.Unix(ts, 0)
	if time.Since(t) > time.Minute*5 {
		return fmt.Errorf("csrf token is expired: %s", t)
	}
	return nil
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
	w.Header().Set("Cross-Origin-Resource-Policy", "same-site")
}

func writeCSRFHeader(w http.ResponseWriter) (string, error) {
	token, err := getCSRF()
	if err != nil {
		return "", err
	}
	w.Header().Add("Set-Cookie",
		fmt.Sprintf("knock-csrf=%s; Max-Age=3000; Path=/; Secure; SameSite=Strict; HttpOnly", token))
	return token, nil
}

var (
	globalToken    string
	globalTokenSha = [sha256.Size]byte{}
)

func checkToken(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Parse Form Error", http.StatusBadRequest)
		return false
	}

	formCsrf := r.FormValue("csrf-token")
	if formCsrf == "" {
		log.Print("no csrf token found in form\n")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return false
	}
	var cookieCsrf string
	for _, v := range r.Cookies() {
		if v.Name == "knock-csrf" {
			cookieCsrf = v.Value
			break
		}
	}
	if cookieCsrf == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Print("no csrf token found in cookie\n")
		return false
	}
	if formCsrf != cookieCsrf {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("csrf mismatch: %s != %s", formCsrf, cookieCsrf)
		return false
	}
	if err := isGoodCSRF(formCsrf); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("error parsing csrf token: %v", err)
		return false
	}
	token := r.Form.Get("token")
	if token != globalToken {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("token mismatch: %s", token)
		return false
	}
	return true
}

var configGroupRE = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)

type configGroup struct {
	Path       string
	Desc       string
	Background bool
	Script     string
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "yes", "y", "on", "true", "1":
		return true, nil
	case "no", "n", "off", "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %s", s)
	}
}

func parseConfigGroup(line string) (*configGroup, error) {
	match := configGroupRE.FindStringSubmatch(line)
	if match == nil {
		return nil, nil
	}
	g := strings.TrimSpace(match[1])
	var cfg configGroup
	parts := strings.Split(g, "#")
	cfg.Path = parts[0]
	p, err := url.Parse(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("bad config group: %s, cause by %w", g, err)
	}
	cfg.Path = p.Path

	for _, part := range parts[1:] {
		keyvalue := strings.SplitN(part, "=", 2)
		if len(keyvalue) != 2 {
			return nil, fmt.Errorf("bad config group: %s", g)
		}
		key := strings.TrimSpace(keyvalue[0])
		value := strings.TrimSpace(keyvalue[1])
		switch key {
		case "desc":
			cfg.Desc = value
		case "background":
			b, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("bad config group: %s, cause by %w", g, err)
			}
			cfg.Background = b
		default:
			return nil, fmt.Errorf("bad config group: %s", g)
		}
	}
	return &cfg, nil
}

type Config struct {
	Groups []*configGroup
}

type templateData struct {
	Config *Config
	Csrf   string
	IPPath string
}

var allSpaceRE = regexp.MustCompile(`^\s*$`)

func isAllSpace(s string) bool {
	return allSpaceRE.MatchString(s)
}

func ParseConfig(r io.Reader) (*Config, error) {
	var (
		config  = &Config{}
		scanner = bufio.NewScanner(r)
		script  strings.Builder
		group   *configGroup
		line    int
	)
	// We need to split by linebreak but keep the '\r';
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	})

	for scanner.Scan() {
		line++
		txt := scanner.Text()
		g, err := parseConfigGroup(txt)
		if err != nil {
			return nil, fmt.Errorf("fail at L%d, %w", line, err)
		}
		if g == nil && group == nil {
			if isAllSpace(txt) {
				continue
			}
			return nil, fmt.Errorf("fail at L%d, no group found", line)
		}
		if g != nil {
			if group != nil {
				group.Script = script.String()
				script.Reset()
				config.Groups = append(config.Groups, group)
			}
			group = g
			continue
		}
		script.WriteString(txt)
		script.WriteByte('\n')
	}
	if group != nil {
		group.Script = script.String()
		config.Groups = append(config.Groups, group)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config: %v", err)
	}
	return config, nil
}

func ParseConfigFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening config file: %v", err)
	}
	return ParseConfig(f)
}

var inheritEnv = []string{
	"TZ", "PATH", "HOME", "LANG",
	"LC_COLLATE", "LC_CTYPE", "LC_MONETARY", "LC_MESSAGES", "LC_NUMERIC", "LC_TIME", "LC_ALL",
}

func runScripts(shell, script string, inBackground bool, envs ...string) error {
	cmd := exec.Command(shell, "-c", script)
	var outout strings.Builder
	cmd.Stdout = &outout
	cmd.Stderr = &outout
	cmd.Dir = os.TempDir()
	cmd.Env = envs
	for _, name := range inheritEnv {
		if !slices.ContainsFunc(cmd.Env, func(e string) bool {
			return strings.HasPrefix(e, name+"=")
		}) {
			v, ok := os.LookupEnv(name)
			if ok {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", name, v))
			}
		}
	}
	if inBackground {
		go func() {
			err := cmd.Run()
			if err != nil {
				log.Printf("error running script: %v, output: %s", err, outout.String())
				return
			}
		}()
		return nil
	}
	err := cmd.Run()
	if err != nil {
		log.Printf("error running script: %v, output: %s", err, outout.String())
		return err
	}
	return nil
}

func getRealIP(r *http.Request) net.IP {
	// Try X-Real-IP first
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return net.ParseIP(realIP)
	}

	// Try X-Forwarded-For
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return net.ParseIP(strings.TrimSpace(ips[0]))
		}
	}

	// Fallback to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

func badIP(ip net.IP) bool {
	return ip == nil || ip.IsUnspecified()
}

func ipString(ip net.IP, ipv4 bool) string {
	if badIP(ip) {
		return ""
	}
	v4 := ip.To4()
	if ipv4 {
		if v4 != nil {
			return v4.String()
		}
		return ""
	}
	if v4 != nil {
		return ""
	}
	return ip.String()
}

var exactHandlers = map[string]http.Handler{}

type wrapResponseWriter struct {
	http.ResponseWriter
	code   int
	length int
}

func (w *wrapResponseWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *wrapResponseWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.length += n
	return n, err
}

// ParseCustomDuration parses a duration string with custom units:
// s = seconds
// m = minutes
// h = hours
// d = days
// y = years
// Example: "1h30m" or "2d5h" or "1y6m"
func ParseCustomDuration(s string) (time.Duration, error) {
	var total time.Duration

	// Split the string into parts
	parts := make([]string, 0)
	var current strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' || r == '.' {
			current.WriteRune(r)
		} else {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		}
	}

	// Process each part
	for _, part := range parts {
		if len(part) < 2 {
			return 0, fmt.Errorf("invalid number in duration: %s", s)
		}

		value, err := strconv.ParseFloat(part[:len(part)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid number in duration: %s", part)
		}

		unit := part[len(part)-1:]
		switch unit {
		case "s":
			total += time.Duration(value * float64(time.Second))
		case "m":
			total += time.Duration(value * float64(time.Minute))
		case "h":
			total += time.Duration(value * float64(time.Hour))
		case "d":
			total += time.Duration(value * 24 * float64(time.Hour))
		case "y":
			total += time.Duration(value * 365 * 24 * float64(time.Hour))
		default:
			return 0, fmt.Errorf("unknown unit: %s", unit)
		}
	}
	return total, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var (
		configFile   string
		rootPath     string
		inBackground bool
		shell        string
		addr         string
		tlsConfig    string
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: knock [OPTION]...\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Knock is a simple tool to knock on a door.\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
		flag.CommandLine.PrintDefaults()
	}
	flag.StringVar(&configFile, "c", "knock.conf", "config file")
	flag.StringVar(&rootPath, "p", "/", "index page path for http server")
	flag.BoolVar(&inBackground, "b", false, "run scripts in background")
	flag.StringVar(&shell, "shell", "bash", "run scripts with this shell")
	flag.StringVar(&addr, "a", ":8080", "address to listen on")
	flag.StringVar(&tlsConfig, "tls", "", "TLS config file, format: cert-file:key-file")
	flag.Parse()
	rootURL, err := url.Parse(rootPath)
	if err != nil {
		log.Fatalf("error parsing root path: %v", err)
	}
	config, err := ParseConfigFile(configFile)
	if err != nil {
		log.Fatalf("error parsing config file: %v", err)
	}
	globalToken = os.Getenv("TOKEN")
	if globalToken == "" {
		log.Fatal("TOKEN environment variable not set")
		return
	}
	globalTokenSha = sha256.Sum256([]byte(globalToken))

	ipPath := rootURL.JoinPath("ip").Path
	exactHandlers[rootURL.Path] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		writeHeader(w, false)
		csrf, err := writeCSRFHeader(w)
		if err != nil {
			log.Printf("error writing csrf header: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		indexTemplate.Execute(w, &templateData{
			Config: config,
			Csrf:   csrf,
			IPPath: ipPath,
		})
	})
	exactHandlers[ipPath] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realIP := getRealIP(r)
		if badIP(realIP) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		if v4 := realIP.To4(); v4 != nil {
			w.Write([]byte(v4.String()))
		} else {
			w.Write([]byte(realIP.String()))
		}
	})
	for _, group := range config.Groups {
		exactHandlers[group.Path] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			if !checkToken(w, r) {
				return
			}

			var formIP net.IP
			if i := r.Form.Get("ip"); i != "" {
				ip := net.ParseIP(i)
				if badIP(ip) {
					log.Printf("invalid IP: %s", i)
					http.Error(w, "Invalid IP: "+i, http.StatusBadRequest)
					return
				}
				formIP = ip
			}
			realIP := getRealIP(r)
			if badIP(realIP) {
				log.Printf("invalid IP: %s", realIP)
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			timeout := r.Form.Get("timeout")
			if timeout == "" {
				timeout = "0s"
			}
			if v := timeout[len(timeout)-1]; v >= '0' && v <= '9' {
				timeout = timeout + "s"
			}
			to, err := ParseCustomDuration(timeout)
			if err != nil || to < time.Second {
				log.Printf("invalid timeout: %s, err:%v", timeout, err)
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			writeHeader(w, true)
			err = runScripts(shell, group.Script,
				inBackground || group.Background,
				fmt.Sprintf("request_ipv6=%s", ipString(realIP, false)),
				fmt.Sprintf("request_ipv4=%s", ipString(realIP, true)),
				fmt.Sprintf("form_ipv6=%s", ipString(formIP, false)),
				fmt.Sprintf("form_ipv4=%s", ipString(formIP, true)),
				fmt.Sprintf("knock_timeout=%d", int64(to.Seconds())),
			)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ww := &wrapResponseWriter{ResponseWriter: w}
		w = ww
		start := time.Now()
		defer func() {
			log.Printf("request: %s %s %d %dbytes %dms",
				r.Method, r.URL.Path, ww.code, ww.length,
				time.Since(start).Milliseconds())
		}()

		if r.Method == http.MethodOptions {
			writeHeader(w, true)
			w.WriteHeader(http.StatusOK)
			return
		}
		if h, ok := exactHandlers[r.URL.Path]; ok {
			h.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	if tlsConfig != "" {
		parts := strings.Split(tlsConfig, ":")
		if len(parts) != 2 {
			log.Fatalf("invalid tls config: %s", tlsConfig)
		}
		certFile := parts[0]
		keyFile := parts[1]
		log.Printf("Listening on %s with TLS\n", addr)
		err = http.ListenAndServeTLS(addr, certFile, keyFile, nil)
	} else {
		log.Printf("Listening on %s\n", addr)
		err = http.ListenAndServe(addr, nil)
	}
	if errors.Is(err, http.ErrServerClosed) {
		log.Println("Server closed")
	} else {
		log.Fatal("Serve exit with ", err)
	}
}

// EncryptString encrypts a string using a password
func EncryptString(plaintext, key []byte) (string, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	// Create a new GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Return the encrypted text as base64 string
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptString decrypts an encrypted string using a password
func DecryptString(encryptedText string, key []byte) (string, error) {
	// Decode the base64 string
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	// Create a new GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Check if the ciphertext is long enough
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	// Extract the nonce
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
