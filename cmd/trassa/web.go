package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ufna/keenetic-trassa/internal/ctl"
	"github.com/ufna/keenetic-trassa/internal/exits"
	"github.com/ufna/keenetic-trassa/internal/rules"
	"github.com/ufna/keenetic-trassa/internal/web"
)

func cmdWeb(args []string, errw io.Writer) int {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	listen := fs.String("listen", "192.168.1.1:8090", "")
	dir := fs.String("dir", defaultDir, "")
	rci := fs.String("rci", defaultRCI, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprint(errw, usage)
		return 2
	}
	useLocalTime()
	logger := log.New(errw, "", log.LstdFlags)
	src := exits.RCI{Base: *rci, Client: &http.Client{Timeout: 3 * time.Second}}
	srv := &web.Server{
		Store: newStore(*dir, *rci),
		Auth:  web.RouterAuth{Base: *rci, Fallback: authFallback(*listen)},
		Daemon: func(cmd, arg string) (string, error) {
			return ctl.Call(sockPath(), cmd, arg, 3*time.Second)
		},
		Tunnels: func(ctx context.Context, cfg *rules.Config) []exits.Tunnel {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return exits.Tunnels(ctx, cfg, src)
		},
		Hosts: []string{*listen},
		Logf:  logger.Printf,
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Printf("web page: %v", err)
		return 1
	}
	// Saving rules waits up to 40 seconds for the daemon, so the write timeout is longer.
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 90 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10, ErrorLog: logger}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	// Shutdown lets requests in progress finish: a save restores the previous rules file when the
	// daemon rejects the new one, and that must not be cut off. The init script waits 10 seconds.
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	}()
	logger.Printf("trassa web page: http://%s/", *listen)
	if err := hs.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Printf("web page: %v", err)
		return 1
	}
	<-stopped
	logger.Print("web page stopped")
	return 0
}

// authFallback is the firmware's own web page on the address the trassa page listens on: some
// firmware issues sign-in challenges only there, not on 127.0.0.1.
func authFallback(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if ip := net.ParseIP(host); err != nil || ip.To4() == nil || ip.IsUnspecified() {
		return ""
	}
	return "http://" + host
}
