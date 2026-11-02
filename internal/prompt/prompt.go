// Package prompt builds a ready-to-paste task for an AI agent (or a human) to fix selected actions: hosts and how
// to reach them, what to fix, the safety rules, the ready fix steps and the re-check command. Shared by the
// dashboard and MCP, so both hand out the same text (the same as the Python implementation's).
package prompt

import (
	"fmt"
	"slices"
	"strings"

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

var texts = map[string]text{
	"en": {
		task: "Task: prepare fixes for findings of the Kanareika security audit — organization {org}{env} ({name}). " +
			"The result is a script the user will run on the server(s) themselves.",
		env: ", environment {env}",
		rules: []string{
			"What to produce:",
			"- One bash script per host: `fix-<host>.sh`. Readable: a short comment before every block, `set -euo pipefail`,",
			"  modes `apply` (default), `verify` and `rollback`, and a summary printed at the end.",
			"- Every change backs up what it touches first (under /var/backups/kanareika/<date>/); `rollback` restores from there.",
			"  Irreversible steps (e.g. removing old kernels) ask for confirmation.",
			"- Base the scripts on the ready steps below; adapt them to the host's OS if needed. Do not add changes that are not in the list.",
			"- sshd: `sshd -t` before reload, and tell the user to keep the current session open until a new login works.",
			"- No reboots and no service restarts with downtime inside the script — print what to do instead.",
			"- You may check the current state read-only over ssh to confirm the steps apply; do not run the scripts yourself.",
			"- Finish with: how to run them (one host first), what to check afterwards, how to roll back.",
		},
		hosts: "Hosts:", host: "- {name}: {os}, exposure {exp}, access: `{route}`", sudo: ", passwordless sudo",
		todo: "What to fix (by priority):", kev: "KEV — exploited in the wild", rce: "pre-auth RCE: {n} CVEs",
		on: "   Hosts: {hosts}", image: "   Image: {v}", path: "   Path: {v}", detail: "   Details: {v}",
		hint: "   Hint: `{v}`", cves: "   CVEs: {n}", due: ", SLA due: {due}",
		script: []string{"Ready steps from Kanareika (tested recipes with backups and rollback) — the basis for the scripts:"},
		check:  "After the user runs the scripts, re-check (from the kanareika directory):",
		end:    "Answer with the scripts and the run instructions.",
	},
	"ru": {
		task: "Задача: подготовить исправления находок аудита безопасности Kanareika — организация {org}{env} ({name}). " +
			"Результат — скрипт, который пользователь сам запустит на сервере (серверах).",
		env: ", окружение {env}",
		rules: []string{
			"Что подготовить:",
			"- По одному bash-скрипту на хост: `fix-<host>.sh`. Читаемый: короткий комментарий перед каждым блоком, `set -euo pipefail`,",
			"  режимы `apply` (по умолчанию), `verify` и `rollback`, в конце — итог.",
			"- Каждое изменение сначала сохраняет то, что меняет (в /var/backups/kanareika/<дата>/); `rollback` восстанавливает оттуда.",
			"  Необратимые шаги (например, удаление старых ядер) спрашивают подтверждение.",
			"- Основа — готовые шаги ниже; при необходимости адаптируй под ОС хоста. Не добавляй изменений, которых нет в списке.",
			"- sshd: `sshd -t` перед reload и напоминание не закрывать текущую сессию, пока не проверен новый вход.",
			"- Никаких перезагрузок и перезапусков сервисов с простоем внутри скрипта — вместо этого выведи, что сделать.",
			"- Можно проверить текущее состояние по ssh только на чтение, чтобы убедиться, что шаги применимы; сам скрипты не запускай.",
			"- В конце: как запускать (сначала один хост), что проверить после, как откатить.",
		},
		hosts: "Хосты:", host: "- {name}: {os}, exposure {exp}, доступ: `{route}`", sudo: ", sudo без пароля",
		todo: "Что исправить (по приоритету):", kev: "KEV — эксплуатируется в атаках", rce: "pre-auth RCE: {n} CVE",
		on: "   Хосты: {hosts}", image: "   Образ: {v}", path: "   Путь: {v}", detail: "   Детали: {v}",
		hint: "   Подсказка: `{v}`", cves: "   CVE: {n}", due: ", срок по SLA: {due}",
		script: []string{"Готовые шаги из Kanareika (проверенные рецепты с резервными копиями и откатом) — основа для скриптов:"},
		check:  "Когда пользователь запустит скрипты, перепроверка (из каталога kanareika):",
		end:    "Ответ: скрипты и инструкция по запуску.",
	},
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
	T, ok := texts[lang]
	if !ok {
		T = texts[i18n.Default]
	}
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
		line := format(T.host, "name", name, "os", osName, "exp", fmt.Sprint(h.Exposure), "route", Route(org, h))
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
		line := fmt.Sprintf("%d. [%s] %s", i+1, prio, i18n.Render(a.Title, a.Msg, a.Args, lang))
		if len(flags) > 0 {
			line += " — " + strings.Join(flags, ", ")
		}
		lines = append(lines, line, format(T.on, "hosts", strings.Join(a.Hosts, ", ")))
		if a.Image != nil && *a.Image != "" {
			lines = append(lines, format(T.image, "v", *a.Image))
		}
		if a.Path != nil && *a.Path != "" {
			lines = append(lines, format(T.path, "v", *a.Path))
		}
		if a.Detail != "" {
			lines = append(lines, format(T.detail, "v", a.Detail)) // no detail_msg in actions: the stored text
		}
		if a.Hint != "" {
			lines = append(lines, format(T.hint, "v", i18n.Render(a.Hint, a.HintMsg, a.HintArgs, lang)))
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
