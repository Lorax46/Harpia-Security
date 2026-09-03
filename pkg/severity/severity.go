package severity

// Severity representa o nível de criticidade de um finding
type Severity string

const (
	Critical      Severity = "critical"
	High          Severity = "high"
	Medium        Severity = "medium"
	Low           Severity = "low"
	Informational Severity = "informational"
)

// Weight retorna o peso numérico da severidade
func (s Severity) Weight() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Informational:
		return 1
	default:
		return 0
	}
}

// IsValid verifica se a severidade é válida
func (s Severity) IsValid() bool {
	switch s {
	case Critical, High, Medium, Low, Informational:
		return true
	}
	return false
}

// All retorna todas as severidades em ordem decrescente
func All() []Severity {
	return []Severity{Critical, High, Medium, Low, Informational}
}
