package httpapi

import (
	"net/http"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/deploy"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
)

// DeployDeps are the services behind the installed-certificate and
// deployment-target routes.
type DeployDeps struct {
	Deploy *deploy.Service
}

func deployError(err error) error {
	var ve *deploy.ValidationError
	if asDeployValidation(err, &ve) {
		return &DetailError{Err: ErrValidation, Detail: map[string]any{"field": ve.Field, "message": ve.Message}}
	}
	return domainError(err)
}

// RegisterDeploy mounts the installed, deployment-target and deploy routes.
func (s *Server) RegisterDeploy(d DeployDeps) {
	s.MustHandle("GET", Prefix+"/installed", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		var cursor time.Time
		if c := q.Get("cursor"); c != "" {
			cursor, _ = time.Parse(time.RFC3339Nano, c)
		}
		items, err := d.Deploy.ListInstalled(r.Context(), subj, q.Get("client_id"), cursor, limitParam(r))
		if err != nil {
			s.fail(w, r, deployError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	s.MustHandle("GET", Prefix+"/deployment-targets", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		items, err := d.Deploy.ListTargets(r.Context(), subj)
		if err != nil {
			s.fail(w, r, deployError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	s.MustHandle("POST", Prefix+"/deployment-targets", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Name   string          `json:"name"`
			Kind   string          `json:"kind"`
			Config sealed.Settings `json:"config"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Deploy.CreateTarget(r.Context(), subj, deploy.TargetInput{Name: in.Name, Kind: in.Kind, Config: in.Config})
		if err != nil {
			s.fail(w, r, deployError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, out)
	})
	s.MustHandle("POST", Prefix+"/certificates/{id}/deploy", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			TargetID string `json:"target_id"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Deploy.Deploy(r.Context(), subj, r.PathValue("id"), in.TargetID)
		if err != nil {
			s.fail(w, r, deployError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
}
