package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/flashbots/go-utils/httplogger"
	"github.com/go-chi/chi/v5"
	"go.uber.org/atomic"
)

type HTTPServerConfig struct {
	ListenAddr string
	Log        *slog.Logger

	DrainDuration            time.Duration
	GracefulShutdownDuration time.Duration
	ReadTimeout              time.Duration
	WriteTimeout             time.Duration
}

type Server struct {
	cfg     *HTTPServerConfig
	isReady atomic.Bool
	log     *slog.Logger

	srv     *http.Server
	handler *FirewallHandler
}

func New(cfg *HTTPServerConfig) (srv *Server, err error) {
	srv = &Server{
		cfg:     cfg,
		log:     cfg.Log,
		srv:     nil,
		handler: NewFirewallHandler(cfg.Log, FirewallConfig{TransitionDuration: 5 * time.Minute}),
	}
	srv.isReady.Swap(true)

	srv.srv = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      srv.getRouter(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return srv, nil
}

func (srv *Server) getRouter() http.Handler {
	mux := chi.NewRouter()

	// Never serve at `/` (root) path
	mux.With(srv.httpLogger).Get("/firewall/status", srv.handler.handleStatus)
	mux.With(srv.httpLogger).Get("/firewall/maintenance", srv.handler.handleMaintenance)
	mux.With(srv.httpLogger).Get("/firewall/production", srv.handler.handleProduction)

	return mux
}

func (srv *Server) httpLogger(next http.Handler) http.Handler {
	return httplogger.LoggingMiddlewareSlog(srv.log, next)
}

func (srv *Server) RunInBackground() {
	// api
	go func() {
		srv.log.Info("Starting HTTP server", "listenAddress", srv.cfg.ListenAddr)
		if err := srv.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srv.log.Error("HTTP server failed", "err", err)
		}
	}()
}

func (srv *Server) Shutdown() {
	// api
	ctx, cancel := context.WithTimeout(context.Background(), srv.cfg.GracefulShutdownDuration)
	defer cancel()
	if err := srv.srv.Shutdown(ctx); err != nil {
		srv.log.Error("Graceful HTTP server shutdown failed", "err", err)
	} else {
		srv.log.Info("HTTP server gracefully stopped")
	}
}
