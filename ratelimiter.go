package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/maypok86/otter"
)

var lock = &sync.Mutex{}

type single struct {
	context context.Context
	cache   otter.Cache[string, string]
	r       *Remote
}

var remoteCache map[*Remote]*single = make(map[*Remote]*single)

func getContext(r *Remote) *single {

	if remoteCache[r] == nil {
		lock.Lock()
		defer lock.Unlock()
		if remoteCache[r] == nil {
			remoteCache[r] = &single{}

			remoteCache[r].context = context.Background()
			remoteCache[r].r = r

			cache, err := otter.MustBuilder[string, string](10_000).
				CollectStats().
				Cost(func(key string, value string) uint32 {
					return 1
				}).DeletionListener(func(key, value string, cause otter.DeletionCause) {
				log.Infof("Evicted %s %s %v ", key, value, cause)

				parts := strings.Split(value, ";")
				if len(parts) < 3 {
					log.Info("Should have had at least three parts")
				} else {
					msg, err := os.ReadFile("/tmp/" + key + ".mail")
					if err != nil {
						log.Errorf("cannot read file %s", key+".mail")

					} else {
						from := parts[1]
						to := parts[2:]
						SendMail(r, from, to, msg)
						os.Remove("/tmp/" + key + ".mail")
					}
				}
			}).
				WithTTL(time.Minute).
				Build()

			if err != nil {
				panic(err)
			}
			remoteCache[r].cache = cache
		}
	}
	return remoteCache[r]
}
