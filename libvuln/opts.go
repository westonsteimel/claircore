package libvuln

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/remind101/migrate"
	"github.com/rs/zerolog"

	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/aws"
	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/libvuln/migrations"
	"github.com/quay/claircore/oracle"
	"github.com/quay/claircore/photon"
	"github.com/quay/claircore/python"
	registry "github.com/quay/claircore/registry/updater"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/suse"
	"github.com/quay/claircore/ubuntu"
)

const (
	DefaultUpdateInterval = 30 * time.Minute
	DefaultUpdateWorkers  = 10
	DefaultMaxConnPool    = 50
)

type Opts struct {
	// The maximum number of database connections in the
	// connection pool.
	MaxConnPool int32
	// A connection string to the database Lbvuln will use.
	ConnString string
	// An interval on which Libvuln will check for new security database
	// updates.
	//
	// This duration will have jitter added to it, to help with smearing load on
	// installations.
	UpdateInterval time.Duration
	// Determines if Livuln will manage database migrations
	Migrations bool
	// A slice of strings representing which updaters libvuln will create.
	//
	// If nil all default UpdaterSets will be used.
	//
	// The following sets are supported:
	// "alpine"
	// "aws"
	// "debian"
	// "oracle"
	// "photon"
	// "pyupio"
	// "rhel"
	// "suse"
	// "ubuntu"
	UpdaterSets []string
	// A list of out-of-tree updaters to run.
	//
	// This list will be merged with any defined UpdaterSets.
	//
	// If you desire no updaters to run do not add an updater
	// into this slice.
	Updaters []driver.Updater
	// A list of out-of-tree matchers you'd like libvuln to
	// use.
	//
	// This list will me merged with the default matchers.
	Matchers []driver.Matcher

	// UpdateWorkers controls the number of update workers running concurrently.
	// If less than or equal to zero, a sensible default will be used.
	UpdateWorkers int

	// If set to true, there will not be a goroutine launched to periodically
	// run updaters.
	DisableBackgroundUpdates bool

	// UpdaterConfigs is a map of functions for configuration of Updaters.
	UpdaterConfigs map[string]driver.ConfigUnmarshaler

	UpdaterFilter func(name string) (keep bool)

	// Client is an http.Client for use by all updaters. If unset,
	// http.DefaultClient will be used.
	Client *http.Client
}

// defaultMatchers is a variable containing
// all the matchers libvuln will use to match
// index records to vulnerabilities.
var defaultMatchers = []driver.Matcher{
	&alpine.Matcher{},
	&aws.Matcher{},
	&debian.Matcher{},
	&oracle.Matcher{},
	&photon.Matcher{},
	&python.Matcher{},
	&rhel.Matcher{},
	&suse.Matcher{},
	&ubuntu.Matcher{},
}

// parse is an internal method for constructing
// the necessary Updaters and Matchers for Libvuln
// usage
func (o *Opts) parse(ctx context.Context) error {
	// required
	if o.ConnString == "" {
		return fmt.Errorf("no connection string provided")
	}

	// optional
	if o.UpdateInterval == 0 || o.UpdateInterval < time.Minute {
		o.UpdateInterval = DefaultUpdateInterval
	}
	// This gives us a ±60 second range, rounded to the nearest tenth of a
	// second.
	const jitter = 120000
	ms := time.Duration(rand.Intn(jitter)-(jitter/2)) * time.Microsecond
	ms = ms.Round(100 * time.Millisecond)
	o.UpdateInterval += ms

	if o.MaxConnPool == 0 {
		o.MaxConnPool = DefaultMaxConnPool
	}
	if o.UpdateWorkers <= 0 {
		o.UpdateWorkers = DefaultUpdateWorkers
	}

	// merge default matchers with any out-of-tree specified
	o.Matchers = append(o.Matchers, defaultMatchers...)

	if o.Client == nil {
		o.Client = http.DefaultClient
	}
	if o.UpdaterConfigs == nil {
		o.UpdaterConfigs = make(map[string]driver.ConfigUnmarshaler)
	}

	return nil
}

// UpdaterSetFunc returns the configured UpdaterSetFactories.
func (o *Opts) updaterSetFunc(ctx context.Context, log zerolog.Logger) ([]driver.UpdaterSetFactory, error) {
	log = log.With().
		Str("component", "libvuln/updaterSets").
		Logger()

	defaults := registry.Registered()

	if o.UpdaterSets != nil {
		for name := range defaults {
			rm := true
			for _, wanted := range o.UpdaterSets {
				if name == wanted {
					rm = false
				}
			}
			if rm {
				delete(defaults, name)
			}
		}
	}
	if err := registry.Configure(ctx, defaults, o.UpdaterConfigs, o.Client); err != nil {
		return nil, err
	}

	fs := make([]driver.UpdaterSetFactory, 0, len(defaults))
	for _, f := range defaults {
		fs = append(fs, f)
	}
	if len(o.Updaters) != 0 {
		// merge determined updaters with any out-of-tree updaters
		us := driver.NewUpdaterSet()
		for _, u := range o.Updaters {
			if err := us.Add(u); err != nil {
				log.Warn().Err(err).Msg("duplicate updater, skipping")
			}
		}
		fs = append(fs, driver.StaticSet(us))
	}
	return fs, nil
}

// Pool creates and returns a configured pxgpool.Pool.
func (o *Opts) pool(ctx context.Context) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(o.ConnString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ConnString: %v", err)
	}
	cfg.MaxConns = o.MaxConnPool

	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Pool: %v", err)
	}
	return pool, nil
}

// Migrations performs migrations if the configuration asks for it.
func (o *Opts) migrations(_ context.Context) error {
	// The migrate package doesn't use the context, which is... disconcerting.
	if !o.Migrations {
		return nil
	}
	cfg, err := pgx.ParseConfig(o.ConnString)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", stdlib.RegisterConnConfig(cfg))
	if err != nil {
		return err
	}
	defer db.Close()

	migrator := migrate.NewPostgresMigrator(db)
	migrator.Table = migrations.MigrationTable
	if err := migrator.Exec(migrate.Up, migrations.Migrations...); err != nil {
		return err
	}

	return nil
}
