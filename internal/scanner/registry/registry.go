package registry

import (
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// Registry armazena todos os checks disponíveis
type Registry struct {
	checks []models.Check
}

// New cria um novo registry
func New() *Registry {
	return &Registry{
		checks: []models.Check{},
	}
}

// Register adiciona um check ao registry
func (r *Registry) Register(check models.Check) {
	r.checks = append(r.checks, check)
}

// All retorna todos os checks registrados
func (r *Registry) All() []models.Check {
	return r.checks
}

// ByProvider filtra checks por provider
func (r *Registry) ByProvider(provider string) []models.Check {
	var result []models.Check
	for _, c := range r.checks {
		if c.Metadata().Provider == provider {
			result = append(result, c)
		}
	}
	return result
}

// ByService filtra checks por serviço
func (r *Registry) ByService(provider, service string) []models.Check {
	var result []models.Check
	for _, c := range r.checks {
		m := c.Metadata()
		if m.Provider == provider && m.ServiceName == service {
			result = append(result, c)
		}
	}
	return result
}

// BySeverity filtra checks por severidade
func (r *Registry) BySeverity(severity string) []models.Check {
	var result []models.Check
	for _, c := range r.checks {
		if c.Metadata().Severity == severity {
			result = append(result, c)
		}
	}
	return result
}

// Count retorna total de checks
func (r *Registry) Count() int {
	return len(r.checks)
}
