package checktest

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/i18n"
)

// Recorded before 0.5, what a module could not read for want of root was written as raw message keys ("cannot
// read: denied.shadow, denied.keys (needs root or sudo)", "no access to denied.dmesg" in the log, "no access to
// docker (privilege=sudo): ..."). It reads in plain words now (check.Denied); the upgrades below turn the recorded
// form into the current one, so the fixtures still check which items were denied and everything else.

var (
	oldDeniedLog = regexp.MustCompile(`no access to ((?:denied\.\w+)(?:, denied\.\w+)*)`)
	oldDocker    = regexp.MustCompile(`^no access to docker \(privilege=\w+\): (.*)$`)
)

// UpgradeLog: a recorded log line in the current words.
func UpgradeLog(s string) string {
	return oldDeniedLog.ReplaceAllStringFunc(s, func(m string) string {
		return check.DeniedLog(strings.Split(oldDeniedLog.FindStringSubmatch(m)[1], ", "))
	})
}

// UpgradeError: a recorded module error in the current words.
func UpgradeError(h config.Host, s string) string {
	m := oldDocker.FindStringSubmatch(s)
	if m == nil {
		return s
	}
	return i18n.T("denied.docker", i18n.Default, map[string]any{"why": check.DeniedWhy(h).Text}) + " (" + m[1] + ")"
}

// UpgradeFinding: a recorded finding (as decoded JSON) in the current words.
func UpgradeFinding(h config.Host, w map[string]any) {
	args, _ := w["args"].(map[string]any)
	what, ok := args["what"].(string)
	if w["msg"] != "health.limited" || !ok {
		return
	}
	title, why := check.Denied(h, strings.Split(what, ", "))
	var keys []any
	for _, k := range strings.Split(what, ", ") {
		keys = append(keys, k)
	}
	w["title"], w["msg"], w["args"] = title.Text, title.Key, map[string]any{"what_keys": keys}
	w["target"], w["target_msg"], w["target_args"] = why.Text, why.Key, map[string]any{"user": h.User}
}

// upgradeFindings: UpgradeFinding over a recorded findings.json.
func upgradeFindings(h config.Host, want string) string {
	var w []map[string]any
	if json.Unmarshal([]byte(want), &w) != nil {
		return want // CompareFindings reports it
	}
	for _, f := range w {
		UpgradeFinding(h, f)
	}
	b, _ := json.Marshal(w) // decoded from JSON: always encodes
	return string(b)
}
