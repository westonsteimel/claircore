package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

func get(ctx context.Context, pool *pgxpool.Pool, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[int][]*claircore.Vulnerability, error) {
	// create a prepared statement
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// start a batch
	batch := &pgx.Batch{}

	// create our bind arguments. the order of dedupedMatchers
	// dictates the order of our bindvar values.
	for _, record := range records {
		if record.Package.Name == "" {
			continue
		}
		query, err := jsonQueryBuilder(record, opts.Matchers)
		if err != nil {
			return nil, fmt.Errorf("error building json query string: %w", err)
		}
		// queue the select query
		batch.Queue(query)
	}
	// send the batch
	tctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := tx.SendBatch(tctx, batch)
	// Can't just defer the close, because the batch must be fully handled
	// before resolving the transaction. Maybe we can move this result handling
	// into its own function to be able to just defer it.

	// gather all the returned vulns for each queued select statement
	results := make(map[int][]*claircore.Vulnerability)
	for _, record := range records {
		rows, err := res.Query()
		if err != nil {
			res.Close()
			return nil, err
		}

		// unpack all returned rows into claircore.Vulnerability structs
		for rows.Next() {
			var id sql.NullInt64
			// fully allocate vuln struct
			v := &claircore.Vulnerability{}

			err := rows.Scan(
				&id,
				&v,
			)
			if err != nil {
				res.Close()
				return nil, fmt.Errorf("failed to scan vulnerability: %v", err)
			}

			// attach id
			v.ID = int(id.Int64)

			// add vulernability to result. handle if array does not exist
			if _, ok := results[record.Package.ID]; !ok {
				vvulns := []*claircore.Vulnerability{v}
				results[record.Package.ID] = vvulns
			} else {
				results[record.Package.ID] = append(results[record.Package.ID], v)
			}
		}
	}
	if err := res.Close(); err != nil {
		return nil, fmt.Errorf("some weird batch error: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit tx: %v", err)
	}
	return results, nil
}
