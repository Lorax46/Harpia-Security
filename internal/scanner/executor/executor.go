package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// Executor orquestra a execução dos checks
type Executor struct{}

// New cria um novo executor
func New() *Executor {
	return &Executor{}
}

// Run executa todos os checks registrados
func (e *Executor) Run(ctx context.Context, checks []models.Check) models.ScanResult {
	result := models.ScanResult{
		Provider:  checks[0].Metadata().Provider,
		Region:    "us-east-1",
		StartedAt: time.Now(),
		Findings:  []models.Finding{},
	}

	summary := models.Summary{}

	for _, check := range checks {
		select {
		case <-ctx.Done():
			result.FinishedAt = time.Now()
			result.Summary = summary
			return result
		default:
		}

		findings, err := check.Execute(ctx)
		if err != nil {
			fmt.Printf("Erro ao executar check %s: %v\n", check.Metadata().CheckID, err)
			continue
		}

		for _, f := range findings {
			f.FoundAt = time.Now()
			result.Findings = append(result.Findings, f)

			switch f.Severity {
			case "critical":
				summary.Critical++
			case "high":
				summary.High++
			case "medium":
				summary.Medium++
			case "low":
				summary.Low++
			case "informational":
				summary.Informational++
			}
		}
	}

	summary.Total = len(result.Findings)
	result.Summary = summary
	result.FinishedAt = time.Now()
	return result
}

// RunSingle executa um único check
func (e *Executor) RunSingle(ctx context.Context, check models.Check) ([]models.Finding, error) {
	return check.Execute(ctx)
}
