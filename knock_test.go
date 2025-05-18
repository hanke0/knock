package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	var cases = []struct {
		s string
		d time.Duration
		e bool
	}{
		{"0s", 0, false},
		{"1s", time.Second, false},
		{"1m", time.Minute, false},
		{"1h", time.Hour, false},
		{"1d", time.Hour * 24, false},
		{"1y", time.Hour * 24 * 365, false},
		{"1d1s", time.Hour*24 + time.Second, false},
		{"1g", 0, true},
	}
	for _, c := range cases {
		d, err := ParseCustomDuration(c.s)
		if err != nil {
			if !c.e {
				t.Errorf("ParseCustomDuration(%s) error: %v", c.s, err)
			}
		} else {
			if c.e {
				t.Errorf("ParseCustomDuration(%s) should error", c.s)
			}
			if d != c.d {
				t.Errorf("ParseCustomDuration(%s) = %v, want %v", c.s, d, c.d)
			}
		}
	}
}

func setupTestConfig(t *testing.T, cfg string) string {
	t.Helper()
	dir := t.TempDir()
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "knock.conf")
	os.WriteFile(dst, []byte(fmt.Sprintf(cfg, dir)), 0644)
	t.Cleanup(func() {
		os.RemoveAll(dir)
	})
	return dir
}

func findTestListenAddr(t *testing.T) string {
	t.Helper()
	addr, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addrStr := addr.Addr().String()
	addr.Close()
	return addrStr
}

func TestServerOK(t *testing.T) {
	cfg := `
	[/knock#desc=knock allow#title=Knock]
	echovar() {
		eval "echo \"$1=\$$1\"">>"%s/knock.log"
	}
	echovar request_ipv4
	echovar request_ipv6
	echovar form_ipv4
	echovar form_ipv4
	echovar knock_timeout
	[ /knock1#desc=knock allow#title=Knock ]
	:
	[/knock2#desc=knock allow#title=Knock ]
	:
	[ /knock3#desc=knock allow#title=Knock]
	: 
	`
	dir := setupTestConfig(t, cfg)
	addr := findTestListenAddr(t)
	setupTestConfig(t, cfg)
	server, err := NewServerWithArgs(
		[]string{"knock",
			"-a", addr,
			"-c", filepath.Join(dir, "knock.conf"),
		})
	if err != nil {
		t.Fatal(err)
	}
	server.Token = t.Name()
	go func() {
		if err := server.ServeForever(); err != nil {
			t.Log(err)
		}
	}()
	time.Sleep(time.Millisecond * 200) // wait for server to start

	http.DefaultClient.Timeout = time.Second
	rsp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if rsp.StatusCode != http.StatusOK {
		t.Fatal("status code not 200", rsp.StatusCode, string(body))
	}
	r, err := regexp.Compile(`name="csrf-token" value="([^"]+)"`)
	if err != nil {
		t.Fatal(err)
	}
	csrf := r.FindSubmatch(body)
	if len(csrf) != 2 {
		t.Fatal("csrf not found")
	}
	csrfToken := string(csrf[1])
	form := url.Values{}
	form.Add("csrf-token", csrfToken)
	form.Add("ip", "1.1.1.1")
	form.Add("timeout", "1d1s")
	form.Add("token", t.Name())
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/knock",
		strings.NewReader(form.Encode()))
	req.Header.Set("X-Real-Ip", "2.2.2.2")
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range rsp.Cookies() {
		req.AddCookie(c)
	}
	rsp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if rsp.StatusCode != http.StatusOK {
		t.Fatal("status code not 200", rsp.StatusCode, string(body))
	}
	if string(body) != "OK" {
		t.Fatal("body not OK", string(body))
	}
	b, err := os.ReadFile(filepath.Join(dir, "knock.log"))
	if err != nil {
		t.Fatal(err)
	}
	expect := `request_ipv4=2.2.2.2
request_ipv6=
form_ipv4=1.1.1.1
form_ipv6=
knock_timeout=86401
`
	if expect != string(b) {
		t.Log("\ngot\n", string(b), "\nexpect\n", expect)
	}
}
