// The registry of root-only read operations. The helper script on servers is rendered from it (RenderHelper), so
// a change here is a change on the servers too: regenerate the helper (`kanareika helper`) and roll it out.

package priv

// PkgDBPaths: paths `docker cp` may read from a container: OS package databases and release files only.
var PkgDBPaths = []string{"/etc/os-release", "/usr/lib/os-release", "/etc/debian_version", "/etc/lsb-release", "/etc/alpine-release", "/etc/redhat-release", "/var/lib/dpkg/status", "/var/lib/dpkg/status.d", "/lib/apk/db/installed", "/var/lib/rpm", "/usr/lib/sysimage/rpm"}

// Ops: name -> shell snippet run as root ("$1".. are validated args) and the argument validators.
var Ops = map[string]Op{
	"dmesg":            {Snippet: "dmesg -T --level=emerg,alert,crit,err,warn 2>&1 | tail -n 400", Args: []Validator{}},
	"journal-errors":   {Snippet: "journalctl -p err --since -7d --no-pager -o short-iso -q 2>&1 | tail -n 1000", Args: []Validator{}},
	"sshd-config":      {Snippet: "sshd -T 2>&1", Args: []Validator{}},
	"sshd-config-user": {Snippet: "sshd -T -C \"user=$1,host=kanareika-probe,addr=203.0.113.10\" 2>&1 | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|usepam) '", Args: []Validator{{Kind: "re", Rule: "[a-z_][a-z0-9_.-]{0,31}"}}},
	"password-users":   {Snippet: "awk -F: '($2 != \"\" && $2 !~ /^[!*]/) {print \"PW:\"$1}' /etc/shadow", Args: []Validator{}},
	"authorized-keys":  {Snippet: "awk -F: '{print $1\" \"$6}' /etc/passwd | while read u h; do for f in \"$h/.ssh/authorized_keys\" \"$h/.ssh/authorized_keys2\"; do [ -f \"$f\" ] && sed \"s|^|K:$u:$f:|\" \"$f\"; done; done 2>/dev/null", Args: []Validator{}},
	"auth-log":         {Snippet: "{ journalctl -u sshd -u ssh --since -30d -o short-iso --no-pager -q 2>/dev/null; for f in $(ls -1tr /var/log/secure /var/log/secure.1 /var/log/secure-[0-9]* /var/log/auth.log /var/log/auth.log.1 2>/dev/null | grep -v '\\.gz$'); do cat \"$f\"; done; } | grep -E 'sshd\\[[0-9]+\\]: (Accepted |Failed |Invalid user )' | tail -n 150000; echo @@auth-readable@@", Args: []Validator{}},
	"sockets":          {Snippet: "ss -Hltnup 2>/dev/null || ss -ltnup 2>/dev/null | tail -n +2", Args: []Validator{}},
	"firewall":         {Snippet: "printf '\\n@@%s@@\\n' firewalld_state; firewall-cmd --state 2>&1; printf '\\n@@%s@@\\n' firewalld; firewall-cmd --list-all-zones 2>/dev/null | head -n 400; printf '\\n@@%s@@\\n' nft; nft list ruleset 2>&1 | head -n 600; printf '\\n@@%s@@\\n' iptables; iptables -S 2>&1 | head -n 600; printf '\\n@@%s@@\\n' iptables_nat; iptables -t nat -S 2>&1 | head -n 300; printf '\\n@@%s@@\\n' ip6tables; ip6tables -S 2>&1 | head -n 200; printf '\\n@@%s@@\\n' ufw; ufw status verbose 2>&1", Args: []Validator{}},
	"docker-version":   {Snippet: "docker version --format '{{json .}}'", Args: []Validator{}},
	"docker-ps":        {Snippet: "docker ps -a --no-trunc --format '{{json .}}'", Args: []Validator{}},
	"docker-running":   {Snippet: "docker ps -q --no-trunc | xargs -r docker inspect --format '{{.Image}} {{.Id}}'", Args: []Validator{}},
	"docker-images":    {Snippet: "docker image ls -q --no-trunc | sort -u | xargs -r docker image inspect", Args: []Validator{}},
	"docker-cp":        {Snippet: "docker cp -L \"$1:$2\" -", Args: []Validator{{Kind: "re", Rule: "[0-9a-f]{64}"}, {Kind: "enum", Enum: PkgDBPaths}}},
	"docker-save":      {Snippet: "docker save \"$1\"", Args: []Validator{{Kind: "re", Rule: "sha256:[0-9a-f]{64}"}}},
	"swarm-info":       {Snippet: "docker info --format '{{json .Swarm}}'", Args: []Validator{}},
	"swarm-nodes":      {Snippet: "docker node ls --format '{{json .}}'", Args: []Validator{}},
	"swarm-services":   {Snippet: "docker service ls --format '{{json .}}'", Args: []Validator{}},
}

// OpOrder: registry order, for a stable helper script.
var OpOrder = []string{"dmesg", "journal-errors", "sshd-config", "sshd-config-user", "password-users", "authorized-keys", "auth-log", "sockets", "firewall", "docker-version", "docker-ps", "docker-running", "docker-images", "docker-cp", "docker-save", "swarm-info", "swarm-nodes", "swarm-services"}
