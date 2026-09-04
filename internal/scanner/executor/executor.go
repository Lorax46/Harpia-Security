package executor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// Check é a interface que todos os checks devem implementar
type Check interface {
	Execute(ctx context.Context, provider interface{}) ([]models.Finding, error)
	Metadata() models.CheckMetadata
}

// Executor orquestra a execução dos checks
type Executor struct {
	checks  []Check
	provider interface{}
}

// New cria um novo executor
func New(provider interface{}, checks ...Check) *Executor {
	return &Executor{
		checks:  checks,
		provider: provider,
	}
}

// Add adiciona um check
func (e *Executor) Add(check Check) {
	e.checks = append(e.checks, check)
}

// Run executa todos os checks em paralelo
func (e *Executor) Run(ctx context.Context) models.ScanResult {
	result := models.ScanResult{
		StartedAt: time.Now(),
		Findings:  []models.Finding{},
	}

	if len(e.checks) > 0 {
		result.Provider = e.checks[0].Metadata().Provider
	}

	var wg sync.WaitGroup
	findingsChan := make(chan []models.Finding, len(e.checks))

	for _, check := range e.checks {
		wg.Add(1)
		go func(c Check) {
			defer wg.Done()

			f, err := c.Execute(ctx, e.provider)
			if err != nil {
				fmt.Printf("Erro ao executar check %s: %v\n", c.Metadata().CheckID, err)
				return
			}
			findingsChan <- f
		}(check)
	}

	wg.Wait()
	close(findingsChan)

	summary := models.Summary{}
	for findings := range findingsChan {
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
