package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/proposal"
	"github.com/Infisical/agent-vault/internal/store"
)

const mcpProtocolVersion = "2025-03-26"

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpRPCError    `json:"error,omitempty"`
}

type mcpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type mcpToolResult struct {
	Content           []map[string]string `json:"content"`
	IsError           bool                `json:"isError,omitempty"`
	StructuredContent any                 `json:"structuredContent,omitempty"`
}

var mcpControlTools = []mcpTool{
	{Name: "vault_proposal_list", Description: "List proposals in the authenticated vault.", InputSchema: mcpObjectSchema(map[string]any{"status": map[string]any{"type": "string", "enum": []string{"pending", "applied", "rejected"}}}, nil)},
	{Name: "vault_proposal_show", Description: "Show safe, non-secret details for a proposal in the authenticated vault.", InputSchema: mcpObjectSchema(map[string]any{"proposal_id": map[string]any{"type": "integer", "minimum": 1}}, []string{"proposal_id"})},
	{Name: "vault_acquisition_start", Description: "Start the acquisition declared by a proposal for one credential key.", InputSchema: mcpObjectSchema(map[string]any{"proposal_id": map[string]any{"type": "integer", "minimum": 1}, "key": map[string]any{"type": "string", "minLength": 1, "maxLength": 128}}, []string{"proposal_id", "key"})},
	{Name: "vault_acquisition_status", Description: "Read safe acquisition status for a proposal, optionally filtered to one credential key.", InputSchema: mcpObjectSchema(map[string]any{"proposal_id": map[string]any{"type": "integer", "minimum": 1}, "key": map[string]any{"type": "string", "minLength": 1, "maxLength": 128}}, []string{"proposal_id"})},
	{Name: "vault_acquisition_cancel", Description: "Cancel an active acquisition for one proposal credential key.", InputSchema: mcpObjectSchema(map[string]any{"proposal_id": map[string]any{"type": "integer", "minimum": 1}, "key": map[string]any{"type": "string", "minLength": 1, "maxLength": 128}}, []string{"proposal_id", "key"})},
	{Name: "vault_approval_open", Description: "Return the authenticated dashboard destination for reviewing a proposal.", InputSchema: mcpObjectSchema(map[string]any{"proposal_id": map[string]any{"type": "integer", "minimum": 1}}, []string{"proposal_id"})},
}

func mcpObjectSchema(properties map[string]any, required []string) map[string]any {
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) != 0 {
		schema["required"] = required
	}
	return schema
}

func (s *Server) handleMCPControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(contentType, "application/json") {
		jsonError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	if !acceptsMCPStreamableHTTP(r.Header.Get("Accept")) {
		jsonError(w, http.StatusNotAcceptable, "Accept must include application/json and text/event-stream")
		return
	}
	var request mcpRequest
	if err := decodeStrictJSON(r, &request); err != nil || request.JSONRPC != "2.0" || request.Method == "" {
		jsonError(w, http.StatusBadRequest, "Invalid JSON-RPC request")
		return
	}
	if len(request.ID) == 0 && request.Method == "notifications/initialized" {
		var params struct{}
		if len(request.Params) != 0 && decodeMCPParams(request.Params, &params) != nil {
			jsonError(w, http.StatusBadRequest, "Invalid notification params")
			return
		}
		if _, authorized := s.authorizeMCPReview(w, r); !authorized {
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if len(request.ID) == 0 || !validMCPID(request.ID) {
		jsonError(w, http.StatusBadRequest, "Invalid JSON-RPC request ID")
		return
	}
	if len(request.Params) == 0 {
		request.Params = json.RawMessage(`{}`)
	}
	vault, authorized := s.authorizeMCPReview(w, r)
	if !authorized {
		return
	}
	response := mcpResponse{JSONRPC: "2.0", ID: request.ID}
	switch request.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string          `json:"protocolVersion"`
			Capabilities    json.RawMessage `json:"capabilities"`
			ClientInfo      json.RawMessage `json:"clientInfo"`
		}
		if err := decodeMCPParams(request.Params, &params); err != nil || params.ProtocolVersion != mcpProtocolVersion || !isJSONObject(params.Capabilities) || !isJSONObject(params.ClientInfo) {
			jsonError(w, http.StatusBadRequest, "Invalid initialize params")
			return
		}
		response.Result = map[string]any{
			"protocolVersion": params.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "agent-vault", "version": "1"},
		}
	case "tools/list":
		var params struct{}
		if err := decodeMCPParams(request.Params, &params); err != nil {
			jsonError(w, http.StatusBadRequest, "Invalid tools/list params")
			return
		}
		response.Result = map[string]any{"tools": mcpControlTools}
	case "tools/call":
		result, err := s.callMCPControlTool(r, vault, request.Params)
		if err != nil {
			response.Result = mcpToolResult{Content: []map[string]string{{"type": "text", "text": err.Error()}}, IsError: true}
		} else {
			encoded, _ := json.Marshal(result)
			response.Result = mcpToolResult{Content: []map[string]string{{"type": "text", "text": string(encoded)}}, StructuredContent: result}
		}
	default:
		response.Error = &mcpRPCError{Code: -32601, Message: "Method not found"}
	}
	jsonStatus(w, http.StatusOK, response)
}

func acceptsMCPStreamableHTTP(header string) bool {
	var acceptsJSON, acceptsEvents bool
	for _, part := range strings.Split(header, ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil || !mcpMediaRangeEnabled(params["q"]) {
			continue
		}
		switch strings.ToLower(mediaType) {
		case "application/json":
			acceptsJSON = true
		case "text/event-stream":
			acceptsEvents = true
		}
	}
	return acceptsJSON && acceptsEvents
}

func mcpMediaRangeEnabled(quality string) bool {
	if quality == "" {
		return true
	}
	value, err := strconv.ParseFloat(quality, 64)
	return err == nil && value > 0 && value <= 1
}

func validMCPID(id json.RawMessage) bool {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(id))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return false
	}
	switch value.(type) {
	case string, json.Number:
		return true
	default:
		return false
	}
}

func decodeMCPParams(raw json.RawMessage, target any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("params must be an object")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 && trimmed[0] == '{'
}

func (s *Server) authorizeMCPReview(w http.ResponseWriter, r *http.Request) (*store.Vault, bool) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, false
	}
	var vault *store.Vault
	var err error
	if sess.VaultID != "" {
		vault, err = s.store.GetVaultByID(r.Context(), sess.VaultID)
	} else {
		name := r.Header.Get("X-Vault")
		if name == "" {
			jsonError(w, http.StatusBadRequest, "Instance-level sessions require X-Vault")
			return nil, false
		}
		vault, err = s.store.GetVault(r.Context(), name)
	}
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, "Vault not found")
		return nil, false
	}
	_, err = s.requireProposalReview(w, r, vault.ID)
	return vault, err == nil
}

func (s *Server) callMCPControlTool(r *http.Request, vault *store.Vault, raw json.RawMessage) (any, error) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := decodeMCPParams(raw, &params); err != nil || params.Name == "" || len(params.Arguments) == 0 {
		return nil, errors.New("invalid tool call")
	}
	if vault == nil {
		return nil, errors.New("vault unavailable")
	}
	switch params.Name {
	case "vault_proposal_list":
		var args struct {
			Status string `json:"status,omitempty"`
		}
		if err := decodeMCPParams(params.Arguments, &args); err != nil || (args.Status != "" && args.Status != "pending" && args.Status != "applied" && args.Status != "rejected") {
			return nil, errors.New("invalid arguments")
		}
		proposals, err := s.store.ListProposals(r.Context(), vault.ID, args.Status)
		if err != nil {
			return nil, errors.New("proposal list unavailable")
		}
		items := make([]mcpProposalSummary, 0, len(proposals))
		for i := range proposals {
			items = append(items, projectMCPProposal(&proposals[i]))
		}
		return map[string]any{"proposals": items}, nil
	case "vault_proposal_show", "vault_approval_open":
		var args struct {
			ProposalID int `json:"proposal_id"`
		}
		if err := decodeMCPParams(params.Arguments, &args); err != nil || args.ProposalID <= 0 {
			return nil, errors.New("invalid arguments")
		}
		proposalRow, err := s.store.GetProposal(r.Context(), vault.ID, args.ProposalID)
		if err != nil || proposalRow == nil {
			return nil, errors.New("proposal not found")
		}
		if params.Name == "vault_approval_open" {
			return map[string]any{"destination": "/vaults/" + url.PathEscape(vault.Name) + "/proposals"}, nil
		}
		return projectMCPProposalDetails(proposalRow)
	case "vault_acquisition_start":
		var args struct {
			ProposalID int    `json:"proposal_id"`
			Key        string `json:"key"`
		}
		if err := decodeMCPParams(params.Arguments, &args); err != nil || args.ProposalID <= 0 || args.Key == "" {
			return nil, errors.New("invalid arguments")
		}
		proposalRow, err := s.store.GetProposal(r.Context(), vault.ID, args.ProposalID)
		if err != nil || proposalRow == nil {
			return nil, errors.New("proposal not found")
		}
		ref, err := proposalAcquisitionRef(proposalRow.CredentialsJSON, args.Key)
		if err != nil || ref == nil {
			return nil, errors.New("credential acquisition declaration unavailable")
		}
		request := mcpInternalRequest(r, http.MethodPost, "/v1/admin/proposals/"+strconv.Itoa(args.ProposalID)+"/acquisitions/"+url.PathEscape(args.Key)+"/start", strings.NewReader(mustJSON(proposalAcquisitionStartRequest{Vault: vault.Name, Handler: ref.Handler, Profile: ref.Profile})))
		request.SetPathValue("id", strconv.Itoa(args.ProposalID))
		request.SetPathValue("key", args.Key)
		return s.invokeMCPAcquisitionHandler(request, s.handleProposalAcquisitionStart)
	case "vault_acquisition_status":
		var args struct {
			ProposalID int    `json:"proposal_id"`
			Key        string `json:"key,omitempty"`
		}
		if err := decodeMCPParams(params.Arguments, &args); err != nil || args.ProposalID <= 0 {
			return nil, errors.New("invalid arguments")
		}
		query := url.Values{"vault": []string{vault.Name}}
		if args.Key != "" {
			query.Set("key", args.Key)
		}
		request := mcpInternalRequest(r, http.MethodGet, "/v1/admin/proposals/"+strconv.Itoa(args.ProposalID)+"/acquisitions?"+query.Encode(), nil)
		request.SetPathValue("id", strconv.Itoa(args.ProposalID))
		return s.invokeMCPAcquisitionHandler(request, s.handleProposalAcquisitionStatus)
	case "vault_acquisition_cancel":
		var args struct {
			ProposalID int    `json:"proposal_id"`
			Key        string `json:"key"`
		}
		if err := decodeMCPParams(params.Arguments, &args); err != nil || args.ProposalID <= 0 || args.Key == "" {
			return nil, errors.New("invalid arguments")
		}
		request := mcpInternalRequest(r, http.MethodPost, "/v1/admin/proposals/"+strconv.Itoa(args.ProposalID)+"/acquisitions/"+url.PathEscape(args.Key)+"/cancel", strings.NewReader(mustJSON(proposalAcquisitionCancelRequest{Vault: vault.Name})))
		request.SetPathValue("id", strconv.Itoa(args.ProposalID))
		request.SetPathValue("key", args.Key)
		return s.invokeMCPAcquisitionHandler(request, s.handleProposalAcquisitionCancel)
	default:
		return nil, errors.New("unknown tool")
	}
}

func mcpInternalRequest(parent *http.Request, method, target string, body io.Reader) *http.Request {
	request := parent.Clone(parent.Context())
	request.Method = method
	request.URL, _ = url.Parse(target)
	request.Body = http.NoBody
	if body != nil {
		request.Body = io.NopCloser(body)
	}
	return request
}

func mustJSON(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func (s *Server) invokeMCPAcquisitionHandler(request *http.Request, handler http.HandlerFunc) (any, error) {
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	if recorder.Code >= http.StatusBadRequest {
		return nil, mcpSafeAcquisitionError(recorder.Body.Bytes())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &raw); err != nil {
		return nil, errors.New("acquisition response unavailable")
	}
	if acquisitions, ok := raw["acquisitions"]; ok {
		var jobs []proposalAcquisitionResponse
		if err := json.Unmarshal(acquisitions, &jobs); err != nil {
			return nil, errors.New("acquisition response unavailable")
		}
		result := make([]mcpAcquisitionStatus, 0, len(jobs))
		for i := range jobs {
			result = append(result, projectMCPAcquisition(jobs[i]))
		}
		return map[string]any{"acquisitions": result}, nil
	}
	var job proposalAcquisitionResponse
	data, ok := raw["data"]
	if ok {
		if err := json.Unmarshal(data, &job); err != nil {
			return nil, errors.New("acquisition response unavailable")
		}
	} else if err := json.Unmarshal(recorder.Body.Bytes(), &job); err != nil {
		return nil, errors.New("acquisition response unavailable")
	}
	return projectMCPAcquisition(job), nil
}

func mcpSafeAcquisitionError(body []byte) error {
	var response struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &response) == nil {
		switch response.Code {
		case "credential_acquisition_disabled", "handler_unavailable", "browser_dom_unavailable", "proposal_acquisition_active", "proposal_context_conflict", "acquisition_mismatch", "proposal_acquisition_state_conflict":
			return errors.New(response.Code)
		}
	}
	return errors.New("acquisition operation failed")
}

type mcpProposalSummary struct {
	ID        int       `json:"proposal_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type mcpServiceSummary struct {
	Action string `json:"action"`
	Name   string `json:"name,omitempty"`
	Host   string `json:"host"`
}

type mcpCredentialSummary struct {
	Action      string                   `json:"action"`
	Key         string                   `json:"key"`
	Type        string                   `json:"type,omitempty"`
	Acquisition *mcpAcquisitionReference `json:"acquisition,omitempty"`
}

type mcpAcquisitionReference struct {
	Handler string `json:"handler"`
	Profile string `json:"profile"`
	Mode    string `json:"mode"`
}

func projectMCPProposal(proposalRow *store.Proposal) mcpProposalSummary {
	return mcpProposalSummary{ID: proposalRow.ID, Status: proposalRow.Status, CreatedAt: proposalRow.CreatedAt}
}

func projectMCPProposalDetails(proposalRow *store.Proposal) (any, error) {
	var services []mcpServiceSummary
	if err := json.Unmarshal([]byte(proposalRow.ServicesJSON), &services); err != nil {
		return nil, errors.New("proposal details unavailable")
	}
	var slots []struct {
		Action      string                   `json:"action"`
		Key         string                   `json:"key"`
		Type        string                   `json:"type,omitempty"`
		Acquisition *proposal.AcquisitionRef `json:"acquisition,omitempty"`
	}
	if err := json.Unmarshal([]byte(proposalRow.CredentialsJSON), &slots); err != nil {
		return nil, errors.New("proposal details unavailable")
	}
	credentials := make([]mcpCredentialSummary, 0, len(slots))
	for _, slot := range slots {
		item := mcpCredentialSummary{Action: slot.Action, Key: slot.Key, Type: slot.Type}
		if slot.Acquisition != nil {
			item.Acquisition = &mcpAcquisitionReference{Handler: slot.Acquisition.Handler, Profile: slot.Acquisition.Profile, Mode: string(slot.Acquisition.Mode)}
		}
		credentials = append(credentials, item)
	}
	return map[string]any{
		"proposal_id": proposalRow.ID, "status": proposalRow.Status, "created_at": proposalRow.CreatedAt,
		"services": services, "credentials": credentials,
	}, nil
}

type mcpAcquisitionStatus struct {
	ID                    string     `json:"acquisition_id"`
	ProposalID            int        `json:"proposal_id"`
	Key                   string     `json:"key"`
	State                 string     `json:"state"`
	ErrorCode             string     `json:"error_code,omitempty"`
	CredentialExpiresAt   *time.Time `json:"credential_expires_at,omitempty"`
	ContinuationExpiresAt *time.Time `json:"continuation_expires_at,omitempty"`
	StartedAt             *time.Time `json:"started_at,omitempty"`
	CompletedAt           *time.Time `json:"completed_at,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

func projectMCPAcquisition(job proposalAcquisitionResponse) mcpAcquisitionStatus {
	return mcpAcquisitionStatus{
		ID: job.ID, ProposalID: job.ProposalID, Key: job.CredentialKey, State: job.State,
		ErrorCode: job.ErrorCode, CredentialExpiresAt: job.CredentialExpiresAt,
		ContinuationExpiresAt: job.ContinuationExpiresAt, StartedAt: job.StartedAt,
		CompletedAt: job.CompletedAt, CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt,
	}
}
