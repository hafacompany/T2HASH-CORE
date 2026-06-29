package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	flagAddr    = flag.String("addr", "127.0.0.1:2331", "آدرس بایند پنل (پیش‌فرض فقط localhost)")
	flagRepo    = flag.String("repo", ".", "مسیر پوشه‌ی پروژه‌ی t2tunnel (جایی که install.sh و .go ها هستند)")
	flagBin     = flag.String("bin", "/usr/local/bin/t2tunnel", "مسیر باینری نصب‌شده")
	flagService = flag.String("service", "t2tunnel", "نام سرویس systemd")
	flagDB      = flag.String("db", "panel.db.json", "مسیر فایل دیتابیس پنل")
)

const Version = "2.3.1"
const GoVersion = "1.22.5"

const ensureGoScript = `
set -e
need=1
if command -v go >/dev/null 2>&1; then
  cur=$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')
  major=$(echo "$cur" | cut -d. -f1)
  minor=$(echo "$cur" | cut -d. -f2)
  if [ "${major:-0}" -gt 1 ] || { [ "${major:-0}" -eq 1 ] && [ "${minor:-0}" -ge 22 ]; }; then
    need=0
  fi
fi
if [ "$need" -eq 1 ]; then
  if command -v snap >/dev/null 2>&1 && snap install go --classic >/dev/null 2>&1; then
    export PATH=$PATH:/snap/bin
  else
    arch=$(uname -m)
    case "$arch" in
      x86_64) goarch="amd64" ;;
      aarch64) goarch="arm64" ;;
      armv7l) goarch="armv6l" ;;
      *) goarch="amd64" ;;
    esac
    apt-get remove -y golang-go >/dev/null 2>&1 || true
    rm -rf /usr/local/go
    curl -fL --retry 3 "https://go.dev/dl/go` + GoVersion + `.linux-${goarch}.tar.gz" -o /tmp/go.tar.gz || true
    [ -f /tmp/go.tar.gz ] && tar -C /usr/local -xzf /tmp/go.tar.gz && rm -f /tmp/go.tar.gz
    grep -q "/usr/local/go/bin" /etc/profile 2>/dev/null || echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    ln -sf /usr/local/go/bin/go /usr/local/bin/go 2>/dev/null || true
  fi
fi
export PATH=$PATH:/usr/local/go/bin:/snap/bin
go env -w GOPROXY=https://goproxy.io,direct 2>/dev/null || true
go env -w GOSUMDB=off 2>/dev/null || true
`

type DB struct {
	User     string `json:"user"`
	PassHash string `json:"pass_hash"`
	Salt     string `json:"salt"`
	mu       sync.Mutex
	path     string
}

func loadDB(path string) (*DB, bool) {
	db := &DB{path: path, User: "admin"}
	b, err := os.ReadFile(path)
	if err != nil {
		return db, false
	}
	_ = json.Unmarshal(b, db)
	db.path = path
	return db, db.PassHash != ""
}

func (d *DB) save() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	b, _ := json.MarshalIndent(d, "", "  ")
	return os.WriteFile(d.path, b, 0600)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashPw(salt, pw string) string {
	h := sha256.Sum256([]byte(salt + ":" + pw))
	return hex.EncodeToString(h[:])
}

func (d *DB) setPassword(pw string) {
	d.Salt = randHex(16)
	d.PassHash = hashPw(d.Salt, pw)
}

func (d *DB) check(user, pw string) bool {
	if subtle.ConstantTimeCompare([]byte(user), []byte(d.User)) != 1 {
		return false
	}
	want, _ := hex.DecodeString(d.PassHash)
	got, _ := hex.DecodeString(hashPw(d.Salt, pw))
	return subtle.ConstantTimeCompare(want, got) == 1
}

type Sessions struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newSessions() *Sessions { return &Sessions{m: map[string]time.Time{}} }

func (s *Sessions) create() string {
	tok := randHex(32)
	s.mu.Lock()
	s.m[tok] = time.Now().Add(8 * time.Hour)
	s.mu.Unlock()
	return tok
}
func (s *Sessions) valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[tok]
	if !ok || time.Now().After(exp) {
		delete(s.m, tok)
		return false
	}
	return true
}
func (s *Sessions) drop(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

type Server struct {
	db   *DB
	sess *Sessions
}

func main() {
	flag.Parse()
	abs, _ := filepath.Abs(*flagRepo)
	*flagRepo = abs

	db, exists := loadDB(*flagDB)
	srv := &Server{db: db, sess: newSessions()}

	if !exists {
		pw := randHex(9)
		db.setPassword(pw)
		if err := db.save(); err != nil {
			log.Fatalf("نمی‌توان دیتابیس را ذخیره کرد: %v", err)
		}
		printFirstRun(*flagAddr, db.User, pw)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/api/login", srv.handleLogin)
	mux.HandleFunc("/api/logout", srv.auth(srv.handleLogout))
	mux.HandleFunc("/api/status", srv.auth(srv.handleStatus))
	mux.HandleFunc("/api/action", srv.auth(srv.handleAction))
	mux.HandleFunc("/api/logs", srv.auth(srv.handleLogs))
	mux.HandleFunc("/api/save-service", srv.auth(srv.handleSaveService))
	mux.HandleFunc("/api/uninstall", srv.auth(srv.handleUninstall))
	mux.HandleFunc("/api/peer", srv.auth(srv.handlePeer))
	mux.HandleFunc("/api/xray/status", srv.auth(srv.handleXrayStatus))
	mux.HandleFunc("/api/xray/install", srv.auth(srv.handleXrayInstall))

	warnIfPublic(*flagAddr)
	log.Printf("T2HASH Panel v%s  →  http://%s   (repo: %s)", Version, *flagAddr, *flagRepo)
	log.Fatal(http.ListenAndServe(*flagAddr, mux))
}

func printFirstRun(addr, user, pw string) {
	line := strings.Repeat("─", 56)
	fmt.Printf("\n\033[38;5;141m%s\033[0m\n", line)
	fmt.Printf("  \033[1;38;5;213mT2HASH Panel v%s — first run\033[0m\n", Version)
	fmt.Printf("\033[38;5;141m%s\033[0m\n", line)
	fmt.Printf("  URL      :  \033[38;5;87mhttp://%s\033[0m\n", addr)
	fmt.Printf("  username :  \033[1m%s\033[0m\n", user)
	fmt.Printf("  password :  \033[1;38;5;83m%s\033[0m\n", pw)
	fmt.Printf("\033[38;5;141m%s\033[0m\n", line)
	fmt.Printf("  \033[38;5;227m! save this password — it is shown only once.\033[0m\n")
	fmt.Printf("  \033[38;5;245m! to reset: delete %s and restart.\033[0m\n", *flagDB)
	fmt.Printf("\033[38;5;141m%s\033[0m\n\n", line)
}

func warnIfPublic(addr string) {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	if host != "" && host != "127.0.0.1" && host != "localhost" {
		log.Printf("\033[38;5;227m[!] WARNING: panel is bound to %s (not localhost). "+
			"Only do this behind nginx+TLS or a firewall. An exposed panel = full root access for anyone.\033[0m", host)
	}
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("t2sess")
		if c == nil || !s.sess.valid(c.Value) {
			writeJSON(w, 401, map[string]any{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method"})
		return
	}
	var in struct{ User, Pass string }
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in)
	time.Sleep(250 * time.Millisecond)
	if !s.db.check(in.User, in.Pass) {
		writeJSON(w, 401, map[string]any{"error": "نام کاربری یا رمز اشتباه است"})
		return
	}
	tok := s.sess.create()
	http.SetCookie(w, &http.Cookie{
		Name: "t2sess", Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: 8 * 3600,
	})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, _ := r.Cookie("t2sess"); c != nil {
		s.sess.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "t2sess", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := map[string]any{
		"version":   Version,
		"repo":      *flagRepo,
		"service":   *flagService,
		"goVersion": firstLine(run("sh", "-c", "export PATH=$PATH:/usr/local/go/bin; go version")),
		"binExists": fileExists(*flagBin),
		"libpcap":   hasLibpcap(),
	}
	active := strings.TrimSpace(run("systemctl", "is-active", *flagService))
	st["serviceActive"] = active == "active"
	st["serviceState"] = active
	writeJSON(w, 200, st)
}

func hasLibpcap() bool {
	return strings.Contains(run("sh", "-c", "ldconfig -p 2>/dev/null | grep libpcap"), "libpcap")
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	var in struct{ Action string }
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in)

	var cmd *exec.Cmd
	switch in.Action {
	case "install-deps":
		cmd = exec.Command("sh", "-c",
			"apt-get update -y && apt-get install -y libpcap-dev build-essential iptables curl tar; "+ensureGoScript)
	case "build":
		cmd = exec.Command("sh", "-c",
			ensureGoScript+
				"cd '"+*flagRepo+"' && [ -f go.mod ] || go mod init t2hash/tunnel; "+
				"export GOTOOLCHAIN=local; export GOPROXY=https://goproxy.io,direct; "+
				"go get github.com/refraction-networking/utls@v1.6.7 && "+
				"go get github.com/xtaci/kcp-go/v5@v5.6.18 && "+
				"go get github.com/google/gopacket && go get github.com/gorilla/websocket && go get github.com/xtaci/smux && "+
				"go mod tidy && go build -trimpath -ldflags '-s -w' -o t2tunnel . && "+
				"install -m 0755 t2tunnel '"+*flagBin+"'")
	case "service-start":
		cmd = exec.Command("systemctl", "start", *flagService)
	case "service-stop":
		cmd = exec.Command("systemctl", "stop", *flagService)
	case "service-restart":
		cmd = exec.Command("systemctl", "restart", *flagService)
	case "service-enable":
		cmd = exec.Command("systemctl", "enable", *flagService)
	case "service-disable":
		cmd = exec.Command("systemctl", "disable", *flagService)
	case "daemon-reload":
		cmd = exec.Command("systemctl", "daemon-reload")
	default:
		writeJSON(w, 400, map[string]any{"error": "عمل ناشناخته"})
		return
	}

	out, err := cmd.CombinedOutput()
	resp := map[string]any{"output": string(out), "ok": err == nil}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, 200, resp)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	out := run("journalctl", "-u", *flagService, "-n", "200", "--no-pager", "-o", "short-iso")
	writeJSON(w, 200, map[string]any{"logs": out})
}

func (s *Server) handleSaveService(w http.ResponseWriter, r *http.Request) {
	var in struct{ Unit string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<18)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad body"})
		return
	}
	if !strings.Contains(in.Unit, "[Service]") || !strings.Contains(in.Unit, "ExecStart=") {
		writeJSON(w, 400, map[string]any{"error": "محتوای سرویس معتبر نیست"})
		return
	}
	path := "/etc/systemd/system/" + *flagService + ".service"
	if err := os.WriteFile(path, []byte(in.Unit), 0644); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	run("systemctl", "daemon-reload")
	writeJSON(w, 200, map[string]any{"ok": true, "path": path})
}

func (s *Server) handleUninstall(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Binary  bool `json:"binary"`
		Service bool `json:"service"`
		Build   bool `json:"build"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in)

	var logs []string
	add := func(format string, a ...any) { logs = append(logs, fmt.Sprintf(format, a...)) }

	if in.Service {
		run("systemctl", "stop", *flagService)
		run("systemctl", "disable", *flagService)
		unit := "/etc/systemd/system/" + *flagService + ".service"
		if err := os.Remove(unit); err == nil {
			add("سرویس حذف شد: %s", unit)
		} else if os.IsNotExist(err) {
			add("سرویس از قبل وجود نداشت")
		} else {
			add("خطا در حذف سرویس: %v", err)
		}
		run("systemctl", "daemon-reload")
	}
	if in.Binary {
		if err := os.Remove(*flagBin); err == nil {
			add("باینری حذف شد: %s", *flagBin)
		} else if os.IsNotExist(err) {
			add("باینری از قبل وجود نداشت")
		} else {
			add("خطا در حذف باینری: %v", err)
		}
	}
	if in.Build {
		for _, name := range []string{"t2tunnel", "rawtest", "rawchantest", "kcprawtest"} {
			p := filepath.Join(*flagRepo, name)
			if err := os.Remove(p); err == nil {
				add("پاک شد: %s", p)
			}
		}
		add("فایل‌های موقت بیلد پاک شدند")
	}

	writeJSON(w, 200, map[string]any{"ok": true, "log": strings.Join(logs, "\n")})
}

func (s *Server) handlePeer(w http.ResponseWriter, r *http.Request) {
	unit := "/etc/systemd/system/" + *flagService + ".service"
	data, err := os.ReadFile(unit)
	if err != nil {
		writeJSON(w, 200, map[string]any{"configured": false, "reachable": false, "reason": "سرویس هنوز ساخته نشده"})
		return
	}
	execLine := ""
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "ExecStart=") {
			execLine = strings.TrimPrefix(strings.TrimSpace(ln), "ExecStart=")
			break
		}
	}
	peers := parsePeers(execLine)
	role := "server"
	if strings.Contains(execLine, "-mode client") {
		role = "client"
	}
	if len(peers) == 0 {
		writeJSON(w, 200, map[string]any{
			"configured": true, "role": role, "reachable": false,
			"reason": "این سمت سرور است؛ منتظر اتصال کلاینت می‌ماند",
		})
		return
	}
	results := make([]map[string]any, 0, len(peers))
	anyUp := false
	for _, p := range peers {
		up := tcpReachable(p, 4*time.Second)
		if up {
			anyUp = true
		}
		results = append(results, map[string]any{"addr": p, "up": up})
	}
	writeJSON(w, 200, map[string]any{
		"configured": true, "role": role, "reachable": anyUp, "peers": results,
	})
}

func parsePeers(execLine string) []string {
	tok := strings.Fields(execLine)
	var out []string
	for i := 0; i < len(tok); i++ {
		switch tok[i] {
		case "-remote":
			if i+1 < len(tok) {
				out = append(out, strings.Trim(tok[i+1], `"`))
			}
		case "-remotes":
			if i+1 < len(tok) {
				for _, p := range strings.Split(strings.Trim(tok[i+1], `"`), ",") {
					if p = strings.TrimSpace(p); p != "" {
						out = append(out, p)
					}
				}
			}
		case "-dstip":
			if i+1 < len(tok) {
				ip := strings.Trim(tok[i+1], `"`)
				port := ""
				for j := 0; j < len(tok)-1; j++ {
					if tok[j] == "-dstport" {
						port = tok[j+1]
					}
				}
				if port != "" {
					out = append(out, ip+":"+port)
				}
			}
		}
	}
	return out
}

func tcpReachable(addr string, timeout time.Duration) bool {
	c, err := netDialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

const xrayBin = "/usr/local/bin/xray"

func (s *Server) handleXrayStatus(w http.ResponseWriter, r *http.Request) {
	ver := ""
	if fileExists(xrayBin) {
		ver = firstLine(run(xrayBin, "version"))
	}
	writeJSON(w, 200, map[string]any{
		"installed": fileExists(xrayBin),
		"version":   ver,
		"arch":      run("sh", "-c", "uname -m | tr -d '\n'"),
	})
}

func (s *Server) handleXrayInstall(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("sh", "-c",
		"bash -c \"$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install")
	out, err := cmd.CombinedOutput()
	resp := map[string]any{"output": string(out), "ok": err == nil}
	if err != nil {
		resp["error"] = err.Error()
	}
	resp["installed"] = fileExists(xrayBin)
	writeJSON(w, 200, resp)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	p := filepath.Join(*flagRepo, "panel.html")
	if b, err := os.ReadFile(p); err == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, "<!doctype html><meta charset=utf-8><body style='font-family:sans-serif;background:#080812;color:#e8e8f5;padding:40px'>"+
		"<h2>panel.html پیدا نشد</h2><p>فایل <code>panel.html</code> را کنار باینری پنل (در پوشه‌ی repo) بگذار.</p>")
}

func run(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return string(out)
}
func netDialTimeout(network, addr string, d time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, d)
}
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}
func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
