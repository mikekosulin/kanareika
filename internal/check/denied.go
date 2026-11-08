package check

import (
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/i18n"
)

// Denied: what a module could not read for want of root, in plain words. denied holds message keys (denied.shadow,
// denied.keys, ...); the title names what was not checked ("Not checked (needs root): /etc/shadow, ..."), the
// detail why, from the host's privilege mode ("audit has no passwordless sudo").
func Denied(h config.Host, denied []string) (title, detail i18n.Text) {
	return i18n.Msg("denied.title", map[string]any{"what_keys": denied}), DeniedWhy(h)
}

// DeniedWhy: why commands that need root were refused on the host.
func DeniedWhy(h config.Host) i18n.Text {
	args := map[string]any{"user": h.User}
	switch {
	case h.User == "root":
		return i18n.Msg("denied.why.root", args)
	case h.Privilege == "sudo":
		return i18n.Msg("denied.why.sudo", args)
	case h.Privilege == "helper":
		return i18n.Msg("denied.why.helper", args)
	}
	return i18n.Msg("denied.why.none", args)
}

// DeniedLog: the same for the scan log: "not checked (needs root): /etc/shadow, ..."; "" when nothing was denied.
func DeniedLog(denied []string) string {
	if len(denied) == 0 {
		return ""
	}
	return i18n.T("denied.log", i18n.Default, map[string]any{"what_keys": denied})
}
