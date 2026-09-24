package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/webhook"
)

// SecretDeps are the services behind the tenant-secret routes.
type SecretDeps struct {
	Secrets *secrets.Service
}

// WebhookDeps are the services behind the webhook routes.
type WebhookDeps struct {
	Webhooks *webhook.Service
}

func secretError(err error) error {
	var ve *secrets.ValidationError
	var ce *secrets.ConflictError
	switch {
	case errors.As(err, &ve):
		return &DetailError{Err: ErrValidation, Detail: map[string]any{"field": ve.Field, "message": ve.Message}}
	case errors.As(err, &ce):
		return ErrConflict
	}
	return domainError(err)
}

func webhookError(err error) error {
	var ve *webhook.ValidationError
	var ce *webhook.ConflictError
	switch {
	case errors.As(err, &ve):
		return &DetailError{Err: ErrValidation, Detail: map[string]any{"field": ve.Field, "message": ve.Message}}
	case errors.As(err, &ce):
		return ErrConflict
	}
	return domainError(err)
}

// RegisterSecrets mounts the tenant-secret routes (contracts §secrets).
func (s *Server) RegisterSecrets(d SecretDeps) {
	s.MustHandle("GET", Prefix+"/secrets", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		items, err := d.Secrets.List(r.Context(), subj)
		if err != nil {
			s.fail(w, r, secretError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	s.MustHandle("POST", Prefix+"/secrets", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Name  string          `json:"name"`
			Kind  string          `json:"kind"`
			Value sealed.Settings `json:"value"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Secrets.Create(r.Context(), subj, secrets.Input{Name: in.Name, Kind: in.Kind, Value: in.Value})
		if err != nil {
			s.fail(w, r, secretError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, out)
	})
	s.MustHandle("PUT", Prefix+"/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Name  string          `json:"name"`
			Kind  string          `json:"kind"`
			Value sealed.Settings `json:"value"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Secrets.Update(r.Context(), subj, r.PathValue("id"), secrets.Input{Name: in.Name, Kind: in.Kind, Value: in.Value})
		if err != nil {
			s.fail(w, r, secretError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("POST", Prefix+"/secrets/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Value sealed.Settings `json:"value"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Secrets.Rotate(r.Context(), subj, r.PathValue("id"), in.Value)
		if err != nil {
			s.fail(w, r, secretError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("POST", Prefix+"/secrets/{id}/remove", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Secrets.Delete(r.Context(), subj, r.PathValue("id")); err != nil {
			s.fail(w, r, secretError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// RegisterWebhooks mounts the webhook routes (contracts §webhooks).
func (s *Server) RegisterWebhooks(d WebhookDeps) {
	s.MustHandle("GET", Prefix+"/webhooks", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		items, err := d.Webhooks.List(r.Context(), subj)
		if err != nil {
			s.fail(w, r, webhookError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	s.MustHandle("POST", Prefix+"/webhooks", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Name       string   `json:"name"`
			URL        string   `json:"url"`
			EventTypes []string `json:"event_types"`
			Secret     string   `json:"secret"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Webhooks.Create(r.Context(), subj, webhook.Input{Name: in.Name, URL: in.URL, EventTypes: in.EventTypes, Secret: in.Secret})
		if err != nil {
			s.fail(w, r, webhookError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, out)
	})
	s.MustHandle("POST", Prefix+"/webhooks/{id}/remove", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Webhooks.Delete(r.Context(), subj, r.PathValue("id")); err != nil {
			s.fail(w, r, webhookError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
