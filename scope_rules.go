package cpauth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
)

// ScopeRule describes where a request for a scope may carry its API key.
type ScopeRule struct {
	UseBearerToken  bool
	HeaderNames     []string
	QueryParamNames []string
}

// ScopeRuleProvider resolves API key extraction rules for a scope.
type ScopeRuleProvider interface {
	LookupScopeRule(ctx context.Context, scope string) (ScopeRule, bool, error)
}

// ScopeRuleProviderFunc adapts a function to ScopeRuleProvider.
type ScopeRuleProviderFunc func(ctx context.Context, scope string) (ScopeRule, bool, error)

func (fn ScopeRuleProviderFunc) LookupScopeRule(ctx context.Context, scope string) (ScopeRule, bool, error) {
	return fn(ctx, scope)
}

// StaticScopeRuleProvider is an in-memory ScopeRuleProvider.
type StaticScopeRuleProvider map[string]ScopeRule

// LookupScopeRule resolves a scope rule by lower-cased scope name.
func (p StaticScopeRuleProvider) LookupScopeRule(_ context.Context, scope string) (ScopeRule, bool, error) {
	if rule, ok := p[scope]; ok {
		return rule, true, nil
	}
	rule, ok := p[strings.ToLower(scope)]
	return rule, ok, nil
}

// DefaultScopeRuleProvider returns the SDK's backward-compatible legacy rules.
func DefaultScopeRuleProvider() ScopeRuleProvider {
	return StaticScopeRuleProvider{
		"oracle": {
			UseBearerToken: true,
		},
		"terminal": {
			HeaderNames: []string{headerLegacyCpTerminal},
		},
		"sourcefinder": {
			HeaderNames: []string{headerLegacySourceFinder},
		},
		"feedstream": {
			HeaderNames:     []string{headerLegacyFeedstream},
			QueryParamNames: []string{headerLegacyFeedstream},
		},
	}
}

// SQLScopeRuleProvider loads scope rules from database/sql.
//
// Query must return use_bearer_token, header_names, and query_param_names for
// one scope. header_names and query_param_names are comma-separated lists.
type SQLScopeRuleProvider struct {
	DB    *sql.DB
	Query string
}

const defaultScopeRuleQuery = `
SELECT use_bearer_token, header_names, query_param_names
FROM auth_scope_rules
WHERE scope = ?
`

// LookupScopeRule resolves a scope rule from SQL.
func (p SQLScopeRuleProvider) LookupScopeRule(ctx context.Context, scope string) (ScopeRule, bool, error) {
	if p.DB == nil {
		return ScopeRule{}, false, errors.New("cpauth: scope rule database is nil")
	}

	query := p.Query
	if query == "" {
		query = defaultScopeRuleQuery
	}

	var useBearer bool
	var headerNames, queryParamNames sql.NullString
	err := p.DB.QueryRowContext(ctx, query, scope).Scan(&useBearer, &headerNames, &queryParamNames)
	if errors.Is(err, sql.ErrNoRows) {
		return ScopeRule{}, false, nil
	}
	if err != nil {
		return ScopeRule{}, false, err
	}

	return ScopeRule{
		UseBearerToken:  useBearer,
		HeaderNames:     splitScopeRuleList(headerNames.String),
		QueryParamNames: splitScopeRuleList(queryParamNames.String),
	}, true, nil
}

func splitScopeRuleList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func extractAPIKeyWithScopeRules(ctx context.Context, r *http.Request, scope string, provider ScopeRuleProvider) (string, error) {
	if v := r.Header.Get(headerAPIKey); v != "" {
		return v, nil
	}
	if provider == nil {
		return "", nil
	}

	rule, ok, err := provider.LookupScopeRule(ctx, scope)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}

	if rule.UseBearerToken {
		if v := extractBearerToken(r); v != "" {
			return v, nil
		}
	}
	for _, headerName := range rule.HeaderNames {
		if v := r.Header.Get(headerName); v != "" {
			return v, nil
		}
	}
	for _, queryParamName := range rule.QueryParamNames {
		if v := r.URL.Query().Get(queryParamName); v != "" {
			return v, nil
		}
	}
	return "", nil
}
