package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/microbatch"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

const (
	selectTombstone    = `SELECT tombstone FROM updatecursor WHERE updater = $1`
	upsertUpdateCurosr = `INSERT INTO updatecursor (updater, hash, tombstone) VALUES 
							($1, $2, $3)
						  ON CONFLICT (updater) 
						  DO UPDATE SET hash = EXCLUDED.hash, tombstone = EXCLUDED.tombstone`
	deleteTombstonedVulns = `DELETE FROM vuln WHERE tombstone = $1`
	insertVulnerability   = `INSERT INTO vuln (updater,
											  vulnerability,
											  tombstone)
							 VALUES ($1, $2, $3);`
)

// putVulnerabilities will begin indexing the list of vulns into the database. a unique constraint
// is placed on this table to ensure deduplication. each new vulnerability is written with a new tombstone
// and each existing vulnerability has their tombstone updated. finally we delete all records with the
// told tombstone as they can be considered stale.
func putVulnerabilities(ctx context.Context, pool *pgxpool.Pool, updater string, hash string, vulns []*claircore.Vulnerability) error {
	// get old tombstone
	var oldTombstone string
	row := pool.QueryRow(ctx, selectTombstone, updater)
	err := row.Scan(&oldTombstone)
	if err != nil {
		if err == pgx.ErrNoRows {
			oldTombstone = ""
		} else {
			return fmt.Errorf("failed to retrieve current tombstone: %v", err)
		}
	}

	// generate new tombstone
	newTombstone := uuid.New().String()

	// start a transaction
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	// safe sized batch inserts to postgres
	mBatcher := microbatch.NewInsert(tx, 2000, time.Minute)
	for _, vuln := range vulns {
		if vuln.Package == nil {
			vuln.Package = &claircore.Package{}
		}
		if vuln.Dist == nil {
			vuln.Dist = &claircore.Distribution{}
		}
		if vuln.Repo == nil {
			vuln.Repo = &claircore.Repository{}
		}
		err := mBatcher.Queue(ctx,
			insertVulnerability,
			updater,
			vuln,
			newTombstone,
		)
		if err != nil {
			return fmt.Errorf("failed to queue vulnerability: %v", err)
		}
	}
	err = mBatcher.Done(ctx)
	if err != nil {
		return fmt.Errorf("failed to finish batch vulnerability insert: %v", err)
	}

	// delete any stale records. if oldTombstone is emptry string this indicates it's
	// our first update and nothiing to delete
	if oldTombstone != "" {
		_, err := tx.Exec(ctx, deleteTombstonedVulns, oldTombstone)
		if err != nil {
			return fmt.Errorf("failed to remove tombstoned records. tx rollback: %v", err)
		}
	}

	// upsert new updatecursor
	_, err = tx.Exec(ctx, upsertUpdateCurosr, updater, hash, newTombstone)
	if err != nil {
		return fmt.Errorf("failed to update updatecursor. tx rollback: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}
	return nil
}
