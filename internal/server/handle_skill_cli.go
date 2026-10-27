package server

import "net/http"

// The embedded agent skill served at GET /v1/skills/cli: the single markdown
// doc compiled into the binary from cmd/skill_cli.md. Unrelated to the
// per-vault Skills resource in handle_skills.go — this one is instance-wide,
// unauthenticated, and read-only.

// SetSkillCLI sets the embedded CLI skill content.
func (s *Server) SetSkillCLI(cli string) {
	s.skillCLI = []byte(cli)
}

func (s *Server) handleSkillCLI(w http.ResponseWriter, r *http.Request) {
	if len(s.skillCLI) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write(s.skillCLI)
}
