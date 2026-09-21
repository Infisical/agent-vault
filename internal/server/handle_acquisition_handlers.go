package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/acquisition"
	"github.com/Infisical/agent-vault/internal/store"
)

type acquisitionHandlerPayload struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	ExecutablePath   string   `json:"executable_path"`
	SHA256           string   `json:"sha256"`
	SigningIdentity  string   `json:"signing_identity,omitempty"`
	AllowedKeys      []string `json:"allowed_keys"`
	AllowedVaults    []string `json:"allowed_vaults"`
	AllowedProfiles  []string `json:"allowed_profiles"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	OutputLimitBytes int      `json:"output_limit_bytes"`
}

type acquisitionHandlerResponse struct {
	acquisitionHandlerPayload
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func newAcquisitionHandlerResponse(handler store.AcquisitionHandler) acquisitionHandlerResponse {
	return acquisitionHandlerResponse{
		acquisitionHandlerPayload: acquisitionHandlerPayload{
			ID:               handler.ID,
			Kind:             handler.Kind,
			ExecutablePath:   handler.ExecutablePath,
			SHA256:           handler.SHA256,
			SigningIdentity:  handler.SigningIdentity,
			AllowedKeys:      handler.AllowedKeys,
			AllowedVaults:    handler.AllowedVaults,
			AllowedProfiles:  handler.AllowedProfiles,
			TimeoutSeconds:   handler.TimeoutSeconds,
			OutputLimitBytes: handler.OutputLimitBytes,
		},
		Enabled:   handler.Enabled,
		CreatedAt: handler.CreatedAt,
		UpdatedAt: handler.UpdatedAt,
	}
}

func (p acquisitionHandlerPayload) storeHandler() store.AcquisitionHandler {
	return store.AcquisitionHandler{
		ID:               p.ID,
		Kind:             p.Kind,
		ExecutablePath:   p.ExecutablePath,
		SHA256:           p.SHA256,
		SigningIdentity:  p.SigningIdentity,
		AllowedKeys:      p.AllowedKeys,
		AllowedVaults:    p.AllowedVaults,
		AllowedProfiles:  p.AllowedProfiles,
		TimeoutSeconds:   p.TimeoutSeconds,
		OutputLimitBytes: p.OutputLimitBytes,
		Enabled:          false,
	}
}

func decodeStrictJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func decodeEmptyJSONObject(r *http.Request) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	var body map[string]json.RawMessage
	if err := decodeStrictJSON(r, &body); err != nil {
		return err
	}
	if len(body) != 0 {
		return fmt.Errorf("request body must be an empty object")
	}
	if body == nil {
		return fmt.Errorf("request body must be an empty object")
	}
	return nil
}

func (s *Server) handleAcquisitionHandlerList(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}
	handlers, err := s.store.ListAcquisitionHandlers(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list handlers")
		return
	}
	result := make([]acquisitionHandlerResponse, 0, len(handlers))
	for _, handler := range handlers {
		result = append(result, newAcquisitionHandlerResponse(handler))
	}
	jsonOK(w, map[string]any{"handlers": result})
}

func (s *Server) handleAcquisitionHandlerRegister(w http.ResponseWriter, r *http.Request) {
	actor, err := s.requireOwnerActor(w, r)
	if err != nil {
		return
	}
	var payload acquisitionHandlerPayload
	if err := decodeStrictJSON(r, &payload); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	handler := payload.storeHandler()
	if err := handler.ValidateRegistration(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := s.store.CreateAcquisitionHandler(r.Context(), handler)
	if errors.Is(err, store.ErrAcquisitionHandlerExists) {
		jsonError(w, http.StatusConflict, "Handler ID already exists")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to register handler")
		return
	}
	s.captureEvent(r, "av.acquisition_handler_registered", actor, map[string]string{"handler_id": created.ID})
	jsonCreated(w, newAcquisitionHandlerResponse(*created))
}

func (s *Server) handleAcquisitionHandlerShow(w http.ResponseWriter, r *http.Request) {
	if _, err := s.requireOwnerActor(w, r); err != nil {
		return
	}
	id := r.PathValue("id")
	if err := store.ValidateAcquisitionHandlerID(id); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid handler ID")
		return
	}
	handler, err := s.store.GetAcquisitionHandler(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "Handler not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read handler")
		return
	}
	jsonOK(w, newAcquisitionHandlerResponse(*handler))
}

func (s *Server) handleAcquisitionHandlerVerify(w http.ResponseWriter, r *http.Request) {
	actor, err := s.requireOwnerActor(w, r)
	if err != nil {
		return
	}
	if err := decodeEmptyJSONObject(r); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	id := r.PathValue("id")
	if err := store.ValidateAcquisitionHandlerID(id); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid handler ID")
		return
	}
	handler, err := s.store.GetAcquisitionHandler(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "Handler not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read handler")
		return
	}
	if err := acquisition.VerifyExecutable(r.Context(), *handler); err != nil {
		unchanged, updateErr := s.store.SetAcquisitionHandlerEnabledIfGeneration(r.Context(), id, handler.Generation, false)
		if updateErr != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to preserve disabled handler state")
			return
		}
		if !unchanged {
			jsonCodedError(w, http.StatusConflict, "handler_changed", "Handler changed during verification")
			return
		}
		code := acquisition.VerificationCode(err)
		s.captureEvent(r, "av.acquisition_handler_verification_failed", actor, map[string]string{"handler_id": id, "error_code": code})
		jsonCodedError(w, http.StatusConflict, code, "Handler verification failed")
		return
	}
	unchanged, err := s.store.SetAcquisitionHandlerEnabledIfGeneration(r.Context(), id, handler.Generation, true)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to enable handler")
		return
	}
	if !unchanged {
		jsonCodedError(w, http.StatusConflict, "handler_changed", "Handler changed during verification")
		return
	}
	verified, err := s.store.GetAcquisitionHandler(r.Context(), id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read verified handler")
		return
	}
	s.captureEvent(r, "av.acquisition_handler_verified", actor, map[string]string{"handler_id": id})
	jsonOK(w, newAcquisitionHandlerResponse(*verified))
}

func (s *Server) handleAcquisitionHandlerDisable(w http.ResponseWriter, r *http.Request) {
	actor, err := s.requireOwnerActor(w, r)
	if err != nil {
		return
	}
	if err := decodeEmptyJSONObject(r); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	id := r.PathValue("id")
	if err := store.ValidateAcquisitionHandlerID(id); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid handler ID")
		return
	}
	if err := s.store.SetAcquisitionHandlerEnabled(r.Context(), id, false); errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "Handler not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to disable handler")
		return
	}
	s.captureEvent(r, "av.acquisition_handler_disabled", actor, map[string]string{"handler_id": id})
	jsonOK(w, map[string]any{"id": id, "enabled": false})
}

func (s *Server) handleAcquisitionHandlerDelete(w http.ResponseWriter, r *http.Request) {
	actor, err := s.requireOwnerActor(w, r)
	if err != nil {
		return
	}
	id := r.PathValue("id")
	if err := store.ValidateAcquisitionHandlerID(id); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid handler ID")
		return
	}
	if err := s.store.DeleteAcquisitionHandler(r.Context(), id); errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "Handler not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to delete handler")
		return
	}
	s.captureEvent(r, "av.acquisition_handler_deleted", actor, map[string]string{"handler_id": id})
	jsonOK(w, map[string]string{"deleted": id})
}
