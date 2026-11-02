# secrets/

Not committed (see `.gitignore`).

By default the key comes from your ssh-agent (`access.key` not set): kanareika talks to the agent and the key
itself is never read or copied. Put files here only if there is no agent:

```
secrets/
  acme/
    id_ed25519          # audit user's SSH key (chmod 600)
    known_hosts         # optional: pinned host keys (learned keys go to reports/<org>/known_hosts)
    kubeconfig-prod     # kubeconfig with a read-only role
```

Paths in `orgs/<org>.yml` are relative to `secrets/`, e.g. `acme/id_ed25519`.
