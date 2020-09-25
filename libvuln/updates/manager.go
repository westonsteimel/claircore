package updates

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
	distlock "github.com/quay/claircore/pkg/distlock"
	"github.com/quay/claircore/updater"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Configs map[string]driver.ConfigUnmarshaler

type Manager struct {
	// a map of factories which will construct run-time configured updaters
	factories map[string]driver.UpdaterSetFactory
	// the number of concurrent updaters running
	workers int
	// a vulnstore.Updater implementation
	store vulnstore.Updater
	// interval to run updaters. if the zero value is provided a caller
	// must explicity call Manager.Run
	interval time.Duration
	// a reslicable set of flattened updaters
	updaters []driver.Updater
	// configs used for factory and updater configuration
	configs Configs
	// a locker to utilize for locking updates
	lock distlock.Locker
}

// NewManager will return a manager ready to have its Start or Run methods called.
//
// Any factory discovered in the updater's registry will have been configured against
// the provided configs.
func NewManager(ctx context.Context, store vulnstore.Updater, lock distlock.Locker, workers int, interval time.Duration, enabled []string, configs Configs, outOfTree []driver.Updater) (*Manager, error) {
	// get registered UpdaterSetFactories
	// it is expected that some other code loads the defaults into this registry
	// if desired.
	factories := updater.Registered()

	// filter them out to only the enabled array
	for _, enable := range enabled {
		for name, _ := range factories {
			if name == enable {
				delete(factories, name)
			}
		}
	}

	if err := updater.Configure(ctx, factories, configs, nil); err != nil {
		return nil, err
	}

	// merge any out of tree updaters
	if len(outOfTree) != 0 {
		// merge determined updaters with any out-of-tree updaters
		us := driver.NewUpdaterSet()
		for _, u := range outOfTree {
			if err := us.Add(u); err != nil {
				log.Warn().Err(err).Msg("duplicate updater, skipping")
			}
		}
		factories["outOfTree"] = driver.StaticSet(us)
	}

	return &Manager{
		store:     store,
		factories: factories,
		workers:   workers,
		interval:  interval,
		lock:      lock,
	}, nil
}

// Start will run updaters at the given interval.
//
// Start is designed to be ran as a go routine.
// Cancel the provided ctx to end the updater loop.
func (m *Manager) Start(ctx context.Context) error {
	if m.interval == 0 {
		return fmt.Errorf("manager must be configured with an interval to start")
	}

	t := time.NewTicker(m.interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			m.Run(ctx)
		}
	}
}

// Run constructs updaters from factories, configures them
// and runs them in Manager.Worker sized groups.
func (m *Manager) Run(ctx context.Context) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/updates/Manager.Run").
		Logger()
	ctx = log.WithContext(ctx)

	// construct updaters, append to flattened slice.
	m.updaters = m.updaters[:0]
	for _, factory := range m.factories {
		set, err := factory.UpdaterSet(ctx)
		if err != nil {
			return err
		}
		m.updaters = append(m.updaters, set.Updaters()...)
	}

	// reconfigure updaters
	for _, u := range m.updaters {
		f, fOK := u.(driver.Configurable)
		cfg, cfgOK := m.configs[u.Name()]
		if fOK && cfgOK {
			if err := f.Configure(ctx, cfg, nil); err != nil {
				log.Warn().Err(err).Msg("failed creating updaters")
				continue
			}
		}
	}
	log.Debug().Int("number", len(m.updaters)).Msg("Batching running updaters")

	errChan := make(chan error, len(m.updaters)+1) // +1 for a potential ctx error
	for i := 0; i < len(m.updaters); i += m.workers {
		if err := ctx.Err(); err != nil {
			errChan <- err
			break
		}

		end := i + m.workers
		if end >= len(m.updaters) {
			end = len(m.updaters)
		}

		var wg sync.WaitGroup
		log.Debug().Int("start", i).Int("end", end).Msg("Starting batch.")
		for j := i; j < end; j++ {
			u := m.updaters[j]
			wg.Add(1)
			go func() {
				defer wg.Done()

				// lock out the db so only one clair process
				// will be updating
				ok, err := m.lock.TryLock(ctx, u.Name())
				if err != nil {
					errChan <- err
					return
				}
				if !ok {
					return
				}
				defer m.lock.Unlock()

				log.Debug().Str("updater", u.Name()).Msg("driving update for updater")
				err = m.driveUpdater(ctx, u)
				log.Debug().Str("updater", u.Name()).Msg("finished driving update for updater")
				if err != nil {
					errChan <- fmt.Errorf("%v: %v\n", u.Name(), err)
				}
			}()
		}
		log.Debug().Int("start", i).Int("end", end).Msg("Waiting for batch to finish.")
		wg.Wait()
		log.Debug().Int("start", i).Int("end", end).Msg("Batch finished.")
	}

	close(errChan)
	if len(errChan) != 0 {
		var b strings.Builder
		b.WriteString("updating errors:\n")
		for err := range errChan {
			fmt.Fprintf(&b, "%v\n", err)
		}
		return errors.New(b.String())
	}
	return nil
}

// driveUpdaters perform the business logic of fetching, parsing, and loading
// vulnerabilities discovered by an updater into the database.
func (m *Manager) driveUpdater(ctx context.Context, u driver.Updater) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libvuln/updates/Manager.driveUpdater").
		Logger()
	ctx = log.WithContext(ctx)

	name := u.Name()
	log.Debug().Str("updater", name).Msg("starting update")

	var prevFP driver.Fingerprint
	opmap, err := m.store.GetUpdateOperations(ctx, name)
	if err != nil {
		return err
	}

	if s := opmap[name]; len(s) > 0 {
		prevFP = s[0].Fingerprint
	}

	vulnDB, newFP, err := u.Fetch(ctx, prevFP)
	if vulnDB != nil {
		defer vulnDB.Close()
	}
	switch {
	case err == nil:
	case errors.Is(err, driver.Unchanged):
		log.Info().Msg("vulnerability database unchanged")
		return nil
	default:
		return err
	}

	vulns, err := u.Parse(ctx, vulnDB)
	if err != nil {
		return fmt.Errorf("failed to parse the fetched vulnerability database: %v", err)
	}

	_, err = m.store.UpdateVulnerabilities(ctx, name, newFP, vulns)
	if err != nil {
		return fmt.Errorf("failed to update vulnerabilities: %v", err)
	}

	log.Debug().Str("updater", name).Msg("finished update")
	return nil
}
