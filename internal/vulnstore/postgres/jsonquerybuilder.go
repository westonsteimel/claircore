package postgres

import (
	"fmt"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	queryTemplate = `vulnerability @> %s`
	kvTemplate    = `'{"%s": { "%s": "%s"}}'`
	and           = `AND`
	or            = `OR`
	space         = ` `
	openParen     = `(`
	closedParen   = `)`
	selectClause  = `SELECT id, vulnerability FROM vuln WHERE`
)

// jsonQueryBuilder creates a jsonb query targeting an interveted index for
// fast key->>value lookup
func jsonQueryBuilder(record *claircore.IndexRecord, matchers []driver.MatchExp) (string, error) {
	// queries will hold 1 or more templated queryTemplate strings
	// these will be 'AND'd together further down
	queries := []string{}

	// do not allow duplicates but retain order
	seen := make(map[driver.MatchExp]struct{})
	for _, m := range matchers {
		if _, ok := seen[m]; ok {
			continue
		}
		switch m {
		case driver.PackageDistributionDID:
			kv := fmt.Sprintf(kvTemplate, "dist", "did", record.Distribution.DID)
			query := fmt.Sprintf(queryTemplate, kv)
			queries = append(queries, query)
		case driver.PackageDistributionName:
			kv := fmt.Sprintf(kvTemplate, "dist", "name", record.Distribution.Name)
			query := fmt.Sprintf(queryTemplate, kv)
			queries = append(queries, query)
		case driver.PackageDistributionVersionCodeName:
			kv := fmt.Sprintf(kvTemplate, "dist", "version_code_name", record.Distribution.VersionCodeName)
			query := fmt.Sprintf(queryTemplate, kv)
			queries = append(queries, query)
		case driver.PackageDistributionVersionID:
			kv := fmt.Sprintf(kvTemplate, "dist", "version_id", record.Distribution.VersionID)
			query := fmt.Sprintf(queryTemplate, kv)
			queries = append(queries, query)
		case driver.PackageDistributionVersion:
			kv := fmt.Sprintf(kvTemplate, "dist", "version", record.Distribution.Version)
			query := fmt.Sprintf(queryTemplate, kv)
			queries = append(queries, query)
		case driver.PackageDistributionArch:
			kv := fmt.Sprintf(kvTemplate, "dist", "arch", record.Distribution.Arch)
			query := fmt.Sprintf(queryTemplate, kv)
			queries = append(queries, query)
		case driver.PackageDistributionCPE:
			kv := fmt.Sprintf(kvTemplate, "dist", "cpe", record.Distribution.CPE)
			query := fmt.Sprintf(queryTemplate, kv)
			queries = append(queries, query)
		case driver.PackageDistributionPrettyName:
			kv := fmt.Sprintf(kvTemplate, "dist", "pretty_name", record.Distribution.PrettyName)
			query := fmt.Sprintf(queryTemplate, kv)
			queries = append(queries, query)
		default:
			return "", fmt.Errorf("was provided unknown matcher: %v", m)
		}
		seen[m] = struct{}{}
	}

	builder := &strings.Builder{}

	// we will always query for package name
	kv := fmt.Sprintf(kvTemplate, "package", "name", record.Package.Name)
	packageQ := fmt.Sprintf(queryTemplate, kv)

	builder.WriteString(selectClause)
	builder.WriteString(space)
	builder.WriteString(openParen)
	builder.WriteString(packageQ)
	builder.WriteString(space)

	// if source package exists add this as an OR returning
	// vulnerabilities which match the source package as well
	if record.Package.Source.Name != "" {
		kv := fmt.Sprintf(kvTemplate, "package", "name", record.Package.Source.Name)
		packageQ := fmt.Sprintf(queryTemplate, kv)
		builder.WriteString(or)
		builder.WriteString(space)
		builder.WriteString(packageQ)
	}
	builder.WriteString(closedParen)
	builder.WriteString(space)

	// fillout rest of match criteria if exists
	for _, query := range queries {
		builder.WriteString(and)
		builder.WriteString(space)
		builder.WriteString(query)
		builder.WriteString(space)
	}

	s := builder.String()
	return s, nil
}
