package main

import (
	_ "embed"
	"os/exec"
	"time"

	"bufio"
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
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

func getCSRF() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func writeHeader(w http.ResponseWriter, raw bool) string {
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
	token := getCSRF()
	w.Header().Add("Set-Cookie",
		fmt.Sprintf("csrf-token=%s; Max-Age=3000; Path=/knock; Secure; SameSite=Strict", token))
	return token
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
		log.Printf("no csrf token found")
		return false
	}
	if token != csrf {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("csrf token mismatch: %s != %s", token, csrf)
		return false
	}
	token = r.Form.Get("token")
	if token != globalToken {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("token mismatch: %s != %s", token, globalToken)
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
		globalToken = getCSRF()
		log.Printf("Generated token: %s", globalToken)
	}
	ipPath := rootURL.JoinPath("ip").Path
	exactHandlers[rootURL.Path] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		csrf := writeHeader(w, false)
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

			writeHeader(w, true)
			err := runScripts(shell, group.Script,
				inBackground || group.Background,
				fmt.Sprintf("request_ipv6=%s", ipString(realIP, false)),
				fmt.Sprintf("request_ipv4=%s", ipString(realIP, true)),
				fmt.Sprintf("form_ipv6=%s", ipString(formIP, false)),
				fmt.Sprintf("form_ipv4=%s", ipString(formIP, true)),
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
		http.ListenAndServeTLS(addr, certFile, keyFile, nil)
	} else {
		log.Printf("Listening on %s\n", addr)
		http.ListenAndServe(addr, nil)
	}
}
