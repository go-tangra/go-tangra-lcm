package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/transfer"
)

// BackupDeps are the services behind the backup export/import routes.
type BackupDeps struct {
	Transfer *transfer.Service
	MaxBytes int64
}

func backupError(err error) error {
	switch {
	case errors.Is(err, transfer.ErrTooLarge):
		return ErrBodyTooLarge
	case errors.Is(err, transfer.ErrInvalid), errors.Is(err, transfer.ErrMode):
		return ErrValidation
	}
	return domainError(err)
}

// RegisterBackup mounts the tenant backup export/import routes.
func (s *Server) RegisterBackup(d BackupDeps) {
	s.MustHandle("POST", Prefix+"/backup/export", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			IncludeCredentials bool `json:"include_credentials"`
		}
		_ = DecodeJSON(r, &in, 0)
		doc, err := d.Transfer.Export(r.Context(), subj, in.IncludeCredentials)
		if err != nil {
			s.fail(w, r, backupError(err))
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="lcm-backup.json"`)
		WriteJSON(w, http.StatusOK, doc)
	})
	s.MustHandle("POST", Prefix+"/backup/import", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		limit := d.MaxBytes
		if limit <= 0 {
			limit = transfer.MaxBytes
		}
		body := http.MaxBytesReader(w, r.Body, limit)
		raw := make([]byte, 0, 64<<10)
		buf := make([]byte, 32<<10)
		for {
			n, rerr := body.Read(buf)
			raw = append(raw, buf[:n]...)
			if rerr != nil {
				var mbe *http.MaxBytesError
				if errors.As(rerr, &mbe) {
					s.fail(w, r, ErrBodyTooLarge)
					return
				}
				break
			}
		}
		doc, err := transfer.DecodeBounded(raw)
		if err != nil {
			s.fail(w, r, backupError(err))
			return
		}
		mode := r.URL.Query().Get("mode")
		if mode == "" {
			mode = "skip"
		}
		rep, err := d.Transfer.Import(r.Context(), subj, doc, mode)
		if err != nil {
			s.fail(w, r, backupError(err))
			return
		}
		WriteJSON(w, http.StatusOK, rep)
	})
}
