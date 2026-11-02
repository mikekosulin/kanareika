package remediate

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Private networks a restricted port stays open to.
var Private = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}

// Recipe is shell run as root on the host. $B is the step's backup directory (set by the plan's prelude).
type Recipe struct {
	Apply, Verify, Rollback string
	Reversible              bool
	Note                    string         // message key, rendered in the plan's language
	NoteArgs                map[string]any // its args
}

// Family of the package manager from the OS name (facts PRETTY_NAME): apt, yum (EL7: no dnf), dnf or unknown.
func Family(osName string) string {
	o := strings.ToLower(osName)
	switch {
	case strings.Contains(o, "debian") || strings.Contains(o, "ubuntu"):
		return "apt"
	case strings.Contains(o, "linux 7") || strings.Contains(o, "release 7"):
		return "yum"
	}
	for _, x := range []string{"centos", "red hat", "rocky", "alma", "oracle", "fedora", "amazon"} {
		if strings.Contains(o, x) {
			return "dnf"
		}
	}
	return "unknown"
}

func rpm(fam string) bool { return fam == "dnf" || fam == "yum" }

var unsafeShell = regexp.MustCompile(`[^\w@%+=:,./-]`)

// Quote a word for sh as Python's shlex.quote does (the scripts must come out the same).
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if !unsafeShell.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// names: the sorted, de-duplicated package names, quoted.
func names(pkgs []string) string {
	u := uniq(pkgs)
	q := make([]string, len(u))
	for i, p := range u {
		q[i] = Quote(p)
	}
	return strings.Join(q, " ")
}

func uniq(pkgs []string) []string {
	u := slices.Clone(pkgs)
	slices.Sort(u)
	return slices.Compact(u)
}

// SSHHardening turns password and/or root password login off. With drop-ins (Include sshd_config.d) the setting goes
// to its own file; without them (CentOS 7) to the top of sshd_config, since sshd takes the first value. `sshd -t`
// guards the reload: a broken config is restored before sshd ever reads it.
func SSHHardening(fam string, password, root bool) Recipe {
	var lines []string
	if password {
		lines = append(lines, "PasswordAuthentication no", "ChallengeResponseAuthentication no") // alias works on old and new sshd
	}
	if root {
		if fam != "yum" {
			lines = append(lines, "PermitRootLogin prohibit-password")
		} else {
			lines = append(lines, "PermitRootLogin without-password")
		}
	}
	body := strings.Join(lines, `\n`) + `\n`
	apply := `
cp -a /etc/ssh/sshd_config "$B/sshd_config"
if grep -qiE '^\s*Include\s+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config; then
  F=/etc/ssh/sshd_config.d/00-kanareika.conf
  [ -f "$F" ] && cp -a "$F" "$B/00-kanareika.conf.prev"
  printf '` + body + `' > "$F"; echo "$F" > "$B/written"
else
  # no drop-ins (e.g. CentOS 7): sshd takes the FIRST value, so put ours at the top
  { printf '# kanareika begin\n` + body + `# kanareika end\n'; cat "$B/sshd_config"; } > /etc/ssh/sshd_config
  echo /etc/ssh/sshd_config > "$B/written"
fi
if ! sshd -t; then echo "sshd -t failed, restoring"; cp -a "$B/sshd_config" /etc/ssh/sshd_config; rm -f /etc/ssh/sshd_config.d/00-kanareika.conf; exit 1; fi
systemctl reload sshd 2>/dev/null || systemctl reload ssh
echo "sshd reloaded; open a NEW session to check key login before closing this one"
`
	rollback := `
cp -a "$B/sshd_config" /etc/ssh/sshd_config
if [ -f "$B/00-kanareika.conf.prev" ]; then cp -a "$B/00-kanareika.conf.prev" /etc/ssh/sshd_config.d/00-kanareika.conf
else rm -f /etc/ssh/sshd_config.d/00-kanareika.conf; fi
sshd -t && { systemctl reload sshd 2>/dev/null || systemctl reload ssh; }
`
	verify := `sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|permitrootlogin) '`
	return Recipe{Apply: apply, Rollback: rollback, Verify: verify, Reversible: true, Note: "fix.ssh"}
}

// Kernel installs the newer kernel; the old one stays installed, so rollback is booting it.
func Kernel(fam string) Recipe {
	if rpm(fam) {
		return Recipe{
			Apply: `
uname -r > "$B/running"; grubby --default-kernel > "$B/default" 2>/dev/null || true
` + fam + ` -y update 'kernel*'
echo "new default: $(grubby --default-kernel 2>/dev/null)"; echo "REBOOT REQUIRED (not done automatically): systemctl reboot"
`,
			Rollback: `
[ -s "$B/default" ] && grubby --set-default "$(cat "$B/default")" && echo "default kernel restored to $(cat "$B/default"); reboot to boot it"
`,
			Verify:     `echo running: $(uname -r); echo default: $(grubby --default-kernel 2>/dev/null)`,
			Reversible: true, Note: "fix.kernel.rpm"}
	}
	return Recipe{Apply: `
uname -r > "$B/running"
apt-get update -q && apt-get install -y --only-upgrade 'linux-image-*'
echo "REBOOT REQUIRED (not done automatically): systemctl reboot"
`, Rollback: `echo "boot the previous kernel ($(cat "$B/running")) from the GRUB menu (Advanced options)"`,
		Verify: `echo running: $(uname -r); ls /boot/vmlinuz-* | tail -3`, Reversible: true, Note: "fix.kernel.deb"}
}

// OSPackages upgrades the given packages; rpm rollback is `history undo` of exactly this transaction, apt
// rollback reinstalls the recorded versions (while the repository still has them).
func OSPackages(fam string, pkgs []string) Recipe {
	n := names(pkgs)
	if rpm(fam) {
		return Recipe{
			Apply: `
` + fam + ` history list 2>/dev/null | awk '$1 ~ /^[0-9]+$/ {print $1; exit}' > "$B/history_before"
` + fam + ` -y upgrade ` + n + `
` + fam + ` history list 2>/dev/null | awk '$1 ~ /^[0-9]+$/ {print $1; exit}' > "$B/history_after"
echo "transaction $(cat "$B/history_after"); services using updated libraries may need a restart: needs-restarting -s"
`,
			Rollback: `
a=$(cat "$B/history_after" 2>/dev/null); b=$(cat "$B/history_before" 2>/dev/null)
if [ -n "$a" ] && [ "$a" != "$b" ]; then ` + fam + ` -y history undo "$a"; else echo "nothing to undo"; fi
`,
			Verify:     "rpm -q " + n + " | head -50",
			Reversible: true, Note: "fix.os.rpm", NoteArgs: map[string]any{"n": len(uniq(pkgs)), "pm": fam}}
	}
	return Recipe{
		Apply: `
dpkg-query -W -f='${Package}=${Version}\n' ` + n + ` 2>/dev/null > "$B/versions_before" || true
apt-get update -q && apt-get install -y --only-upgrade ` + n + `
`,
		Rollback: `
xargs -a "$B/versions_before" apt-get install -y --allow-downgrades || echo "some old versions are no longer in the repository"
`,
		Verify: "dpkg-query -W " + n + " | head -50", Reversible: true, Note: "fix.os.deb"}
}

// NTP installs and enables chrony; rollback disables it only if it was not enabled before.
func NTP(fam string) Recipe {
	inst := map[string]string{"dnf": "dnf -y install chrony", "yum": "yum -y install chrony", "apt": "apt-get install -y chrony"}[fam]
	if inst == "" {
		inst = "true"
	}
	svc := "chronyd"
	if fam == "apt" {
		svc = "chrony"
	}
	return Recipe{Apply: `
systemctl is-enabled ` + svc + ` > "$B/was_enabled" 2>/dev/null || echo disabled > "$B/was_enabled"
` + inst + `
systemctl enable --now ` + svc + `
`, Rollback: `grep -q enabled "$B/was_enabled" || systemctl disable --now ` + svc,
		Verify:     "timedatectl 2>/dev/null | grep -i synchron; chronyc tracking 2>/dev/null | head -5",
		Reversible: true, Note: "fix.ntp"}
}

// Rpcbind: a public port 111 owned by rpcbind (or socket-activated by systemd) is closed by turning rpcbind off.
func Rpcbind() Recipe {
	return Recipe{Apply: `
systemctl is-enabled rpcbind.socket > "$B/socket" 2>/dev/null || true; systemctl is-enabled rpcbind > "$B/service" 2>/dev/null || true
systemctl disable --now rpcbind.socket rpcbind.service
`, Rollback: `
grep -q enabled "$B/socket" && systemctl enable --now rpcbind.socket
grep -q enabled "$B/service" && systemctl enable --now rpcbind.service; true
`, Verify: "ss -Hlnp | grep -w 111 || echo 'port 111 closed'", Reversible: true, Note: "fix.rpcbind"}
}

// RestrictPort adds a temporary (non-persistent) firewall rule: only private networks may reach the port. Reboot
// or a firewalld reload removes it — a natural safety net; make it permanent in the provisioner once confirmed.
// Docker-published ports bypass INPUT, so they are filtered in DOCKER-USER by the original destination port.
func RestrictPort(port int, proto string, docker bool) Recipe {
	tag := fmt.Sprintf("kanareika-%s-%d", proto, port)
	chain, match := "INPUT", fmt.Sprintf("-p %s --dport %d", proto, port)
	if docker {
		chain, match = "DOCKER-USER", fmt.Sprintf("-p %s -m conntrack --ctorigdstport %d", proto, port)
	}
	accepts := make([]string, len(Private))
	for i, n := range Private {
		accepts[i] = fmt.Sprintf("iptables -I %s %s -s %s -m comment --comment %s -j ACCEPT", chain, match, n, tag)
	}
	return Recipe{Apply: fmt.Sprintf(`
iptables -S %[1]s > "$B/%[1]s.before"
iptables -I %[1]s %[2]s -m comment --comment %[3]s -j DROP
%[4]s
echo "%[5]s/%[6]d: only private networks allowed (temporary rule, reboot/firewalld reload removes it)"
`, chain, match, tag, strings.Join(accepts, "\n"), proto, port),
		Rollback: fmt.Sprintf(`
iptables -S %s | grep -- '--comment %s' | sed 's/^-A /-D /' | while read -r r; do iptables $r; done
`, chain, tag),
		Verify:     fmt.Sprintf("iptables -S %s | grep -- '%s' || echo 'no kanareika rule'", chain, tag),
		Reversible: true, Note: "fix.port", NoteArgs: map[string]any{"chain": chain}}
}

// Reboot: the new kernel is installed; the step checks what will (not) come back and leaves the reboot to a human.
// Swarm services with restart_policy other than `any` exit 0 on shutdown and stay down after a reboot.
// The long docker lines are joined with spaces where Python's source had a backslash-newline continuation.
func Reboot(fam string) Recipe {
	def := "ls -t /boot/vmlinuz-* | head -1"
	if rpm(fam) {
		def = "grubby --default-kernel 2>/dev/null"
	}
	return Recipe{Apply: `
uname -r > "$B/running"; ` + def + ` > "$B/default" 2>/dev/null || true
echo "running: $(cat "$B/running")  ->  after reboot: $(cat "$B/default")"
if docker info --format '{{.Swarm.ControlAvailable}}' 2>/dev/null | grep -q true; then
  docker service ls -q | xargs -r docker service inspect --format '{{.Spec.Name}} {{.Spec.TaskTemplate.RestartPolicy.Condition}}'     | awk '$2 != "any" {print "WARNING: " $1 " restart_policy=" $2 " - may stay down after reboot: docker service update --force " $1}'
  docker service ls --format '{{.Name}} {{.Replicas}}' > "$B/services_before"
fi
echo "REBOOT (not done automatically): systemctl reboot"
`, Rollback: `
[ -s "$B/running" ] && echo "previous kernel: $(cat "$B/running") - pick it in GRUB or: grubby --set-default /boot/vmlinuz-$(cat "$B/running")"
`, Verify: `echo "running: $(uname -r)"
docker info --format '{{.Swarm.ControlAvailable}}' 2>/dev/null | grep -q true &&   docker service ls --format '{{.Name}} {{.Replicas}}' | awk '{split($2, r, "/"); if (r[1] != r[2]) print "NOT RUNNING: " $0}'; true`,
		Reversible: true, Note: "fix.reboot"}
}

// Mitigations: packages whose vulnerable part is a service that is often installed but not needed; stopping it
// removes the exposure until the vendor ships the fix. Only services — a library cannot be "turned off".
var Mitigations = map[string][]string{"rsync": {"rsyncd.socket", "rsyncd.service"}, "rsync-daemon": {"rsyncd.socket", "rsyncd.service"},
	"cups": {"cups.socket", "cups.service"}, "avahi": {"avahi-daemon.socket", "avahi-daemon.service"},
	"openssh-server": {}, "samba": {"smb.service", "nmb.service"}, "telnet-server": {"telnet.socket"}}

// VendorCheck: has an update appeared since the scan? Read-only, so apply and verify are the same.
func VendorCheck(fam string, pkgs []string) Recipe {
	var q string
	if rpm(fam) {
		q = fam + " -q --refresh check-update " + names(pkgs) +
			"; [ $? = 100 ] && echo 'UPDATE AVAILABLE NOW: run the OS packages fix' || echo 'still nothing to install'"
	} else {
		q = "apt-get update -q >/dev/null && apt list --upgradable 2>/dev/null | grep -E '^(" + strings.Join(uniq(pkgs), "|") +
			")/' || echo 'still nothing to install'"
	}
	return Recipe{Apply: q, Rollback: "true", Verify: q, Reversible: true, Note: "fix.vendor.check"}
}

// VendorUsers lists the running processes that map the packages' files: that is where the risk is.
func VendorUsers(fam string, pkgs []string) Recipe {
	lister := "dpkg -L"
	if rpm(fam) {
		lister = "rpm -ql"
	}
	return Recipe{Apply: `
for p in ` + names(pkgs) + `; do
  ` + lister + ` "$p" 2>/dev/null | grep -E '\.so(\.|$)|/s?bin/|/libexec/' > "$B/$p.files"
  pids=$(for d in /proc/[0-9]*; do { readlink "$d/exe"; awk '{print $6}' "$d/maps"; } 2>/dev/null | grep -qxF -f "$B/$p.files" && echo "${d#/proc/}"; done)
  echo "== $p: $(echo $pids | wc -w) processes"
  [ -n "$pids" ] && ps -o comm= -p $(echo $pids | tr ' ' ,) | sort | uniq -c | sort -rn | head -15
done; true
`, Rollback: "true", Verify: "true", Reversible: true, Note: "fix.vendor.users"}
}

// DisableUnits stops and disables the units that are enabled or active, remembering which, so rollback brings
// back exactly those.
func DisableUnits(units []string, what string) Recipe {
	u := strings.Join(units, " ")
	return Recipe{Apply: `
for u in ` + u + `; do systemctl is-enabled "$u" 2>/dev/null | grep -q enabled && echo "$u" >> "$B/enabled"; done
for u in ` + u + `; do systemctl is-active "$u" 2>/dev/null | grep -q '^active' && echo "$u" >> "$B/active"; done
if [ -s "$B/enabled" ] || [ -s "$B/active" ]; then systemctl disable --now ` + u + ` 2>/dev/null; echo "stopped: $(cat "$B/enabled" "$B/active" 2>/dev/null | sort -u | tr '\n' ' ')"
else echo "` + what + `: service not running — nothing to stop (only the client part is installed)"; fi
`, Rollback: `
[ -s "$B/enabled" ] && xargs -r systemctl enable < "$B/enabled"
[ -s "$B/active" ] && xargs -r systemctl start < "$B/active"; true
`, Verify: "systemctl is-active " + u + " 2>/dev/null | paste -sd' '; true", Reversible: true,
		Note: "fix.vendor.mitigate", NoteArgs: map[string]any{"what": what}}
}

// OldKernels removes unused old kernels: irreversible, the list is kept for reference.
func OldKernels(fam string) Recipe {
	cmd := map[string]string{"dnf": "dnf -y remove --oldinstallonly", "yum": "package-cleanup -y --oldkernels --count=2",
		"apt": "apt-get -y autoremove --purge"}[fam]
	if cmd == "" {
		cmd = "true"
	}
	return Recipe{Apply: "rpm -q kernel > \"$B/kernels\" 2>/dev/null || true\n" + cmd + "\n",
		Rollback: `echo "removed kernels cannot be restored automatically: see $B/kernels"`,
		Verify:   "rpm -q kernel 2>/dev/null || dpkg -l 'linux-image-*' | grep ^ii", Reversible: false, Note: "fix.old_kernels"}
}
