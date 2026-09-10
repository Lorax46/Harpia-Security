package registry

import (
	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
)

// Registry armazena todos os checks disponíveis
type Registry struct {
	checks []executor.Check
}

// New cria um novo registry
func New() *Registry {
	return &Registry{
		checks: []executor.Check{},
	}
}

// Register adiciona um check ao registry
func (r *Registry) Register(check executor.Check) {
	r.checks = append(r.checks, check)
}

// All retorna todos os checks registrados
func (r *Registry) All() []executor.Check {
	return r.checks
}

// Count retorna total de checks
func (r *Registry) Count() int {
	return len(r.checks)
}
