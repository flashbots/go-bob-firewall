package httpserver

import (
	"log/slog"
	"net/http"
	"os/exec"
	"sync"
	"time"
)

type FirewallConfig struct {
	TransitionDuration time.Duration
}

type FirewallHandler struct {
	log *slog.Logger

	lock                         sync.Mutex
	mode                         FirewallMode
	transitionToMaintenanceStart *time.Time // Optional - possibly nil

	config FirewallConfig
}

func NewFirewallHandler(log *slog.Logger, config FirewallConfig) *FirewallHandler {
	return &FirewallHandler{
		log:    log,
		mode:   Maintenance,
		config: config,
	}
}

func (h *FirewallHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	h.lock.Lock()
	defer h.lock.Unlock()

	w.Write([]byte(h.mode.String()))
}

func (h *FirewallHandler) applyNFTables(fm FirewallMode) error {
	if h.lock.TryLock() {
		panic("applyNFTables but lock is not held!")
	}

	h.log.Info("applying nftables", "current_mode", h.mode, "apply_mode", fm)
	var args []string
	switch fm {
	case Maintenance:
		args = []string{"-f", "/etc/nftables-maintenance.conf"}
	case Production:
		args = []string{"-f", "/etc/nftables-production.conf"}
	case TransitionToMaintenance:
		args = []string{"-f", "/etc/nftables-transition.conf"}
	default:
		panic("invalid trusted firewall mode passed, refusing to continue")
	}

	output, err := exec.Command("/usr/sbin/nft", args...).CombinedOutput()
	if err != nil {
		h.log.With("output", output).With("error", err).Error("could not apply nftables configuration")
	}

	return err
}

func (h *FirewallHandler) handleMaintenance(w http.ResponseWriter, r *http.Request) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if h.mode != Production {
		http.Error(w, "invalid maintenance transition request not from production mode", http.StatusBadRequest)
		return
	}

	err := h.applyNFTables(TransitionToMaintenance)
	if err != nil {
		err = h.applyNFTables(Production)
		if err != nil {
			// TODO: handle this case
			panic("irrecoverable state - could not revert nftables transition")
		}
		http.Error(w, "could not execute transition", http.StatusInternalServerError)
		return
	}
	// TODO: also drop existing established connections (once)

	*h.transitionToMaintenanceStart = time.Now()
	h.mode = TransitionToMaintenance

	go func() {
		time.Sleep(h.config.TransitionDuration)

		h.lock.Lock()
		defer h.lock.Unlock()

		if h.mode != TransitionToMaintenance {
			panic("invalid transition state, refusing to continue")
		}
		err := h.applyNFTables(Maintenance)
		if err == nil {
			// Everything OK!
			h.mode = Maintenance
			return
		}

		h.log.Error("failed to apply maintenance firewall rules", "error", err)

		// Try to revert back to production. If that also fails, panic - irrecoverable state.
		err = h.applyNFTables(Production)
		if err != nil {
			h.log.Error("failed to apply revert to production after failed maintenance transition", "error", err)

			// TODO: handle this case
			panic("could not revert after failed transition attempt, refusing to continue")
		}

		// Revert OK
		h.mode = Production
	}()

	w.WriteHeader(http.StatusOK)
}

func (h *FirewallHandler) handleProduction(w http.ResponseWriter, r *http.Request) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if h.mode != Maintenance {
		http.Error(w, "invalid production transition request not from maintenance mode", http.StatusBadRequest)
		return
	}

	err := h.applyNFTables(Production)
	if err != nil {
		err := h.applyNFTables(Maintenance)
		if err != nil {
			panic("irrecoverable state")
		}
	}

	// TODO: drop established connections

	h.mode = Production

	w.WriteHeader(http.StatusOK)
}

type FirewallMode uint32

const (
	Maintenance FirewallMode = iota
	Production
	TransitionToMaintenance
)

func (fm FirewallMode) String() string {
	switch fm {
	case Maintenance:
		return "maintenance"
	case Production:
		return "production"
	case TransitionToMaintenance:
		return "transition_to_maintenance"
	default:
		return "unknown"
	}
}
