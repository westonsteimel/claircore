package postgres

import (
	"fmt"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

const (
	openArray    = `{`
	closeArray   = `}`
	quote        = `"`
	comma        = `,`
	space        = ` `
	selectClause = `SELECT id,
		name,
		description,
		links,
		severity,
		package_name,
		package_version,
		package_kind,
		dist_id,
		dist_name,
		dist_version,
		dist_version_code_name,
		dist_version_id,
		dist_arch,
		dist_cpe,
		dist_pretty_name,
		repo_name,
		repo_key,
		repo_uri,
		fixed_in_version
		FROM vuln WHERE tags @> '%s'`
)

func tagQueryBuilder(record *claircore.IndexRecord, matchers []driver.MatchExp) (string, error) {
	// queries will hold 1 or more templated queryTemplate strings
	// these will be 'AND'd together further down
	tags := []string{}

	// do not allow duplicates but retain order
	seen := make(map[driver.MatchExp]struct{})
	for _, m := range matchers {
		if _, ok := seen[m]; ok {
			continue
		}
		switch m {
		case driver.PackageDistributionDID:
			tags = append(tags, record.Distribution.DID)
		case driver.PackageDistributionName:
			tags = append(tags, record.Distribution.Name)
		case driver.PackageDistributionVersionCodeName:
			tags = append(tags, record.Distribution.VersionCodeName)
		case driver.PackageDistributionVersionID:
			tags = append(tags, record.Distribution.VersionID)
		case driver.PackageDistributionVersion:
			tags = append(tags, record.Distribution.Version)
		case driver.PackageDistributionArch:
			tags = append(tags, record.Distribution.Arch)
		case driver.PackageDistributionCPE:
			tags = append(tags, record.Distribution.CPE)
		case driver.PackageDistributionPrettyName:
			tags = append(tags, record.Distribution.PrettyName)
		default:
			return "", fmt.Errorf("was provided unknown matcher: %v", m)
		}
		seen[m] = struct{}{}
	}

	builder := &strings.Builder{}

	// begin building tags to search on
	builder.WriteString(openArray)
	builder.WriteString(quote)
	builder.WriteString(record.Package.Name)
	builder.WriteString(quote)

	// if source package exists add this as an OR returning
	// vulnerabilities which match the source package as well
	if record.Package.Source.Name != "" {
		builder.WriteString(comma)
		builder.WriteString(space)
		builder.WriteString(quote)
		builder.WriteString(record.Package.Source.Name)
		builder.WriteString(quote)
	}

	// fillout rest of match criteria if exists
	for _, tag := range tags {
		builder.WriteString(comma)
		builder.WriteString(space)
		builder.WriteString(quote)
		builder.WriteString(tag)
		builder.WriteString(quote)
	}
	builder.WriteString(closeArray)

	tagsArray := builder.String()
	query := fmt.Sprintf(selectClause, tagsArray)
	return query, nil
}
