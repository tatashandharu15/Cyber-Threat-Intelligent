// Package service implements the ATT&CK Reference service's business logic:
// validation and upsert of MITRE ATT&CK techniques (a synchronous sync), seeding
// of a built-in technique set, and read passthroughs. The catalog is global
// reference data, so there is no tenant context and no Kafka eventing.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/siberindo/cti/services/attack-reference-service/internal/domain"
	"github.com/siberindo/cti/services/attack-reference-service/internal/store"
)

// ValidationError carries a human-readable validation message.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func newValidation(format string, a ...any) *ValidationError {
	return &ValidationError{msg: fmt.Sprintf(format, a...)}
}

// IsValidation reports whether err is a ValidationError.
func IsValidation(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}

// ErrNotFound is re-exported from the store for the API layer.
var ErrNotFound = store.ErrNotFound

// Store is the persistence contract.
type Store interface {
	UpsertTechnique(ctx context.Context, t *domain.Technique) (*domain.Technique, error)
	GetByTechniqueID(ctx context.Context, techniqueID string) (*domain.Technique, error)
	ListTechniques(ctx context.Context, fil domain.TechniqueFilter) ([]domain.Technique, error)
	Count(ctx context.Context) (int, error)
}

// Service holds the ATT&CK reference business logic dependencies.
type Service struct {
	store Store
	log   *slog.Logger
}

// New constructs a Service.
func New(s Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: s, log: log}
}

// Sync validates and upserts a batch of techniques (the synchronous equivalent of
// a MITRE STIX feed sync). Each technique must carry a well-formed technique_id and
// a non-empty name; the first invalid entry aborts the batch with a validation
// error so a partial, inconsistent sync is never persisted. It returns the number
// of techniques upserted.
func (s *Service) Sync(ctx context.Context, techniques []domain.Technique) (int, error) {
	if len(techniques) == 0 {
		return 0, newValidation("at least one technique is required")
	}
	for i := range techniques {
		if err := validate(&techniques[i]); err != nil {
			return 0, err
		}
	}
	inserted := 0
	for i := range techniques {
		if _, err := s.store.UpsertTechnique(ctx, &techniques[i]); err != nil {
			return inserted, err
		}
		inserted++
	}
	return inserted, nil
}

func validate(t *domain.Technique) error {
	if !validTechniqueID(t.TechniqueID) {
		return newValidation("invalid technique_id %q (expected e.g. T1566 or T1566.001)", t.TechniqueID)
	}
	if t.Name == "" {
		return newValidation("name is required for technique %s", t.TechniqueID)
	}
	return nil
}

// SeedDefaults upserts the built-in set of well-known ATT&CK techniques so the
// service is queryable immediately without an external sync. It returns the number
// of techniques upserted.
func (s *Service) SeedDefaults(ctx context.Context) (int, error) {
	return s.Sync(ctx, defaultTechniques())
}

// ListTechniques returns techniques matching the filter.
func (s *Service) ListTechniques(ctx context.Context, fil domain.TechniqueFilter) ([]domain.Technique, error) {
	return s.store.ListTechniques(ctx, fil)
}

// GetTechnique returns one technique by its ATT&CK id.
func (s *Service) GetTechnique(ctx context.Context, techniqueID string) (*domain.Technique, error) {
	return s.store.GetByTechniqueID(ctx, techniqueID)
}

// ptr returns a pointer to v. Used to populate optional technique fields.
func ptr[T any](v T) *T { return &v }

// defaultTechniques is the built-in seed catalog: a curated set of well-known
// MITRE ATT&CK techniques with accurate ids, names, and tactic short-names. It is
// intentionally small (the full catalog is loaded via Sync from the STIX feed).
func defaultTechniques() []domain.Technique {
	return []domain.Technique{
		{
			TechniqueID: "T1566", Name: "Phishing",
			Description:  "Adversaries may send phishing messages to gain access to victim systems.",
			TacticRefs:   []string{"initial-access"},
			PlatformRefs: []string{"Linux", "macOS", "Windows", "Office 365", "SaaS", "Google Workspace"},
		},
		{
			TechniqueID: "T1566.001", Name: "Spearphishing Attachment",
			Description:       "Adversaries may send spearphishing emails with a malicious attachment to gain access to victim systems.",
			TacticRefs:        []string{"initial-access"},
			PlatformRefs:      []string{"Linux", "macOS", "Windows"},
			IsSubtechnique:    true,
			ParentTechniqueID: ptr("T1566"),
		},
		{
			TechniqueID: "T1078", Name: "Valid Accounts",
			Description:  "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access.",
			TacticRefs:   []string{"initial-access", "persistence", "privilege-escalation", "defense-evasion"},
			PlatformRefs: []string{"Linux", "macOS", "Windows", "SaaS", "IaaS", "Containers"},
		},
		{
			TechniqueID: "T1110", Name: "Brute Force",
			Description:  "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.",
			TacticRefs:   []string{"credential-access"},
			PlatformRefs: []string{"Linux", "macOS", "Windows", "Office 365", "SaaS", "IaaS"},
		},
		{
			TechniqueID: "T1486", Name: "Data Encrypted for Impact",
			Description:  "Adversaries may encrypt data on target systems to interrupt availability to system and network resources.",
			TacticRefs:   []string{"impact"},
			PlatformRefs: []string{"Linux", "macOS", "Windows", "IaaS"},
		},
		{
			TechniqueID: "T1071", Name: "Application Layer Protocol",
			Description:  "Adversaries may communicate using OSI application layer protocols to avoid detection by blending in with existing traffic.",
			TacticRefs:   []string{"command-and-control"},
			PlatformRefs: []string{"Linux", "macOS", "Windows"},
		},
		{
			TechniqueID: "T1041", Name: "Exfiltration Over C2 Channel",
			Description:  "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
			TacticRefs:   []string{"exfiltration"},
			PlatformRefs: []string{"Linux", "macOS", "Windows"},
		},
		{
			TechniqueID: "T1190", Name: "Exploit Public-Facing Application",
			Description:  "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to gain initial access.",
			TacticRefs:   []string{"initial-access"},
			PlatformRefs: []string{"Linux", "macOS", "Windows", "Network", "Containers", "IaaS"},
		},
		{
			TechniqueID: "T1059", Name: "Command and Scripting Interpreter",
			Description:  "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
			TacticRefs:   []string{"execution"},
			PlatformRefs: []string{"Linux", "macOS", "Windows", "Network"},
		},
		{
			TechniqueID: "T1053", Name: "Scheduled Task/Job",
			Description:  "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
			TacticRefs:   []string{"execution", "persistence", "privilege-escalation"},
			PlatformRefs: []string{"Linux", "macOS", "Windows", "Containers"},
		},
		{
			TechniqueID: "T1505", Name: "Server Software Component",
			Description:  "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems.",
			TacticRefs:   []string{"persistence"},
			PlatformRefs: []string{"Linux", "macOS", "Windows", "Network"},
		},
		{
			TechniqueID: "T1567", Name: "Exfiltration Over Web Service",
			Description:  "Adversaries may use an existing, legitimate external Web service to exfiltrate data.",
			TacticRefs:   []string{"exfiltration"},
			PlatformRefs: []string{"Linux", "macOS", "Windows", "Office 365", "SaaS"},
		},
		{
			TechniqueID: "T1598", Name: "Phishing for Information",
			Description:  "Adversaries may send phishing messages to elicit sensitive information that can be used during targeting.",
			TacticRefs:   []string{"reconnaissance"},
			PlatformRefs: []string{"PRE"},
		},
		{
			TechniqueID: "T1583", Name: "Acquire Infrastructure",
			Description:  "Adversaries may buy, lease, or rent infrastructure that can be used during targeting.",
			TacticRefs:   []string{"resource-development"},
			PlatformRefs: []string{"PRE"},
		},
		{
			TechniqueID: "T1204", Name: "User Execution",
			Description:  "An adversary may rely upon specific actions by a user in order to gain execution.",
			TacticRefs:   []string{"execution"},
			PlatformRefs: []string{"Linux", "macOS", "Windows", "IaaS", "Containers"},
		},
	}
}
