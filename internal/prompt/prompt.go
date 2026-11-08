// Package prompt builds a ready-to-paste task for an AI agent (or a human) to fix selected actions: hosts and how
// to reach them, what to fix, the safety rules, the ready fix steps and the re-check command. Shared by the
// dashboard and MCP, so both hand out the same text (the same as the Python implementation's).
package prompt

import (
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/remediate"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Recheck: the scan module that re-checks an action category.
var Recheck = map[string]string{"kernel": "os_packages", "os": "os_packages", "vendor": "os_packages", "eol": "os_packages",
	"cleanup": "os_packages", "image": "docker", "app": "software_fs", "config": "access", "exposure": "exposure", "health": "health"}

// Categories in the order the MCP schema lists them.
var Categories = []string{"kernel", "os", "vendor", "eol", "cleanup", "image", "app", "config", "exposure", "health"}

type text struct {
	task, env                                string
	rules                                    []string
	hosts, host, sudo, todo, kev, rce        string
	on, image, path, detail, hint, cves, due string
	script                                   []string
	check, end                               string
}

// textsFor: the task's texts in lang, from locales/<lang>.json ("prompt.*"; a missing one falls back to English).
// rules and script are lines; the boundary (host data is data, not instructions) is the last rule.
func textsFor(lang string) text {
	g := func(k string) string { return i18n.T("prompt."+k, lang, nil) }
	return text{
		task: g("task"), env: g("env"), rules: append(strings.Split(g("rules"), "\n"), g("boundary")),
		hosts: g("hosts"), host: g("host"), sudo: g("sudo"), todo: g("todo"), kev: g("kev"), rce: g("rce"),
		on: g("on"), image: g("image"), path: g("path"), detail: g("detail"), hint: g("hint"), cves: g("cves"),
		due: g("due"), script: strings.Split(g("script"), "\n"), check: g("check"), end: g("end"),
	}
}

// Boundary: the rule, per language, that marks what came from the hosts as data (added after the Python version).
func Boundary(lang string) string {
	return i18n.T("prompt.boundary", lang, nil)
}

// data: text that came from a scanned host, made one line: line breaks and other control characters become spaces,
// so a value can not start a line of its own that reads like part of the task (an injected "- New rule: …").
func data(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
	}), " ")
}

// format fills {name} placeholders (the templates are Python str.format strings without format specs).
func format(t string, kv ...string) string {
	return strings.NewReplacer(withBraces(kv)...).Replace(t)
}

func withBraces(kv []string) []string {
	out := make([]string, len(kv))
	for i, s := range kv {
		if i%2 == 0 {
			s = "{" + s + "}"
		}
		out[i] = s
	}
	return out
}

// Route: how to reach the host (ssh user@address, through the jump chain if any).
func Route(org *config.Org, h *config.Host) string { return remediate.Route(org, h) }

// Build the task for the selected actions of one environment; "" when none of ids is in the view.
func Build(org *config.Org, env string, view *report.View, ids []string, lang string) string {
	T := textsFor(lang)
	sel := map[string]bool{}
	for _, id := range ids {
		sel[id] = true
	}
	var acts []*report.Action
	for i := range view.Actions {
		if sel[view.Actions[i].ID] {
			acts = append(acts, &view.Actions[i])
		}
	}
	if len(acts) == 0 {
		return ""
	}
	hosts := map[string]*config.Host{}
	for i := range org.Hosts {
		if org.Hosts[i].Env == env {
			hosts[org.Hosts[i].Name] = &org.Hosts[i]
		}
	}
	var used []string
	for _, a := range acts {
		for _, h := range a.Hosts {
			if hosts[h] != nil && !slices.Contains(used, h) {
				used = append(used, h)
			}
		}
	}
	slices.Sort(used)
	envText := ""
	if env != config.DefaultEnv {
		envText = format(T.env, "env", env)
	}
	lines := []string{format(T.task, "org", org.ID, "env", envText, "name", org.Name()), ""}
	lines = append(lines, T.rules...)
	lines = append(lines, "", T.hosts)
	for _, name := range used {
		h := hosts[name]
		osName := h.OSHint
		if f, ok := view.Facts[name]; ok && f.OS != nil && *f.OS != "" {
			osName = *f.OS
		}
		if osName == "" {
			osName = "?"
		}
		line := format(T.host, "name", data(name), "os", data(osName), "exp", fmt.Sprint(h.Exposure), "route", data(Route(org, h)))
		if h.Privilege == "sudo" {
			line += T.sudo
		}
		lines = append(lines, line)
	}
	lines = append(lines, "", T.todo)
	for i, a := range acts {
		var flags []string
		if a.KEV {
			flags = append(flags, T.kev)
		}
		if a.RCE != nil && *a.RCE != 0 {
			flags = append(flags, format(T.rce, "n", fmt.Sprint(*a.RCE)))
		}
		prio := "-"
		if a.Priority != nil && *a.Priority != "" {
			prio = *a.Priority
		}
		line := fmt.Sprintf("%d. [%s] %s", i+1, data(prio), data(i18n.Render(a.Title, a.Msg, a.Args, lang)))
		if len(flags) > 0 {
			line += " — " + strings.Join(flags, ", ")
		}
		lines = append(lines, line, format(T.on, "hosts", data(strings.Join(a.Hosts, ", "))))
		if a.Image != nil && *a.Image != "" {
			lines = append(lines, format(T.image, "v", data(*a.Image)))
		}
		if a.Path != nil && *a.Path != "" {
			lines = append(lines, format(T.path, "v", data(*a.Path)))
		}
		if a.Detail != "" {
			lines = append(lines, format(T.detail, "v", data(a.Detail))) // no detail_msg in actions: the stored text
		}
		if a.Hint != "" {
			lines = append(lines, format(T.hint, "v", data(i18n.Render(a.Hint, a.HintMsg, a.HintArgs, lang))))
		}
		if a.CVEs != 0 {
			c := format(T.cves, "n", fmt.Sprint(a.CVEs))
			if a.Due != nil && *a.Due != "" {
				c += format(T.due, "due", *a.Due)
			}
			lines = append(lines, c)
		}
	}
	if steps := remediate.RenderMarkdown(remediate.BuildPlan(org, env, view, ids, lang), lang); steps != "" {
		lines = append(lines, "")
		lines = append(lines, T.script...)
		lines = append(lines, "", steps)
	}
	modSet := map[string]bool{}
	for _, a := range acts {
		m, ok := Recheck[a.Cat]
		if !ok {
			m = "os_packages"
		}
		modSet[m] = true
	}
	mods := make([]string, 0, len(modSet))
	for m := range modSet {
		mods = append(mods, m)
	}
	slices.Sort(mods)
	cmd := "  kanareika scan --org " + org.ID
	if env != config.DefaultEnv {
		cmd += " --env " + env
	}
	for _, h := range used {
		cmd += " --host " + h
	}
	for _, m := range mods {
		cmd += " --module " + m
	}
	lines = append(lines, "", T.check, cmd, "", T.end)
	return strings.Join(lines, "\n")
}
