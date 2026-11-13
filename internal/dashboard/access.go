package dashboard

import (
	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/illumio/plugger/internal/registry"
)

// accessLevels resolves the PCE access level (readonly | readwrite) shown as a
// badge for each installed plugin.
//
// Precedence per plugin:
//  1. the installed manifest's own access field;
//  2. the cached registry entry — covers plugins installed by a plugger build
//     that predates the field, whose stored manifest therefore has none;
//  3. readonly, the manifest default (least privilege).
//
// Only the on-disk registry cache is consulted so page renders never block on
// the network; a registry fetch (registry page, update check) refreshes it.
func (h *Handler) accessLevels(plugins []*plugin.Plugin) map[string]string {
	out := make(map[string]string, len(plugins))
	var fromRegistry map[string]string
	for _, p := range plugins {
		if p.Manifest.Access != "" {
			out[p.Name] = p.Manifest.Access
			continue
		}
		if fromRegistry == nil {
			fromRegistry = h.registryAccess()
		}
		if a, ok := fromRegistry[p.Name]; ok {
			out[p.Name] = a
			continue
		}
		out[p.Name] = config.AccessReadOnly
	}
	return out
}

// registryAccess maps plugin name -> declared access from the cached registries.
func (h *Handler) registryAccess() map[string]string {
	out := map[string]string{}
	mgr := registry.NewManager(h.deps.Config.Plugger.DataDir)
	for _, reg := range mgr.LoadCached() {
		for _, rp := range reg.Plugins {
			if rp.Access == "" {
				continue
			}
			if _, seen := out[rp.Name]; !seen {
				out[rp.Name] = rp.Access
			}
		}
	}
	return out
}
