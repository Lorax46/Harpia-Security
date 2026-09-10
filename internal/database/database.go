// Package database provides database connection and models for the CNAPP platform.
package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB is the global database connection
var DB *gorm.DB

// Config holds database configuration
type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
	SSLMode  string
}

// NewConfig creates a database config from environment variables
func NewConfig() Config {
	return Config{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     getEnv("DB_PORT", "5432"),
		User:     getEnv("DB_USER", "horus"),
		Password: getEnv("DB_PASSWORD", "horus"),
		Database: getEnv("DB_NAME", "horus"),
		SSLMode:  getEnv("DB_SSLMODE", "disable"),
	}
}

// Connect establishes a connection to the database
func Connect(cfg Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database, cfg.SSLMode,
	)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := DB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	log.Println("[database] Connected successfully")
	return DB, nil
}

// Migrate runs auto-migration for all models
func Migrate() error {
	if DB == nil {
		return fmt.Errorf("database connection is nil")
	}

	err := DB.AutoMigrate(
		&models.User{},
		&models.Provider{},
		&models.Scan{},
		&models.Finding{},
		&models.ComplianceReport{},
		&models.ComplianceControl{},
		&models.Inventory{},
		&models.InventoryChange{},
		&models.Vulnerability{},
		&models.ASMAsset{},
		&models.SOARPlaybook{},
		&models.DSPMAsset{},
		&models.APIKey{},
		&models.AuditLog{},
		&models.ScheduledScan{},
		&models.Notification{},
		&models.Integration{},
		&models.Setting{},
	)

	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	log.Println("[database] Migration completed successfully")
	return nil
}

// Health checks database connectivity
func Health() error {
	if DB == nil {
		return fmt.Errorf("database connection is nil")
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}

	return sqlDB.Ping()
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
