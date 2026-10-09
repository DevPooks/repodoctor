package model

type SourceType string

const (
	SourceRegistry SourceType = "registry"
	SourceGit      SourceType = "git"
	SourceGitHub   SourceType = "github"
	SourceLocal    SourceType = "local"
	SourceHTTP     SourceType = "http"
	SourceUnknown  SourceType = "unknown"
)

type Dependency struct {
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	Constraint string     `json:"constraint,omitempty"`
	Ecosystem  string     `json:"ecosystem"`
	Direct     bool       `json:"direct"`
	SourceType SourceType `json:"source_type"`
	Source     string     `json:"source,omitempty"`
	Manifest   string     `json:"manifest"`
	Line       int        `json:"line,omitempty"`
}

func (d Dependency) HasExactVersion() bool {
	if d.Version == "" || d.SourceType != SourceRegistry {
		return false
	}
	for _, prefix := range []string{"^", "~", ">", "<", "=", "*", "latest", "workspace:"} {
		if len(d.Version) >= len(prefix) && d.Version[:len(prefix)] == prefix {
			return false
		}
	}
	return true
}
