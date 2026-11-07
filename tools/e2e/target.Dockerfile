# The scan target of the Linux end-to-end check: a Debian host with sshd and a read-only audit user
# (key login only, as the provisioner sets it up). The public key is mounted at run time.
# Root on purpose (trivy DS-0002): sshd starts as root, as on the servers it stands for; logins are the unprivileged audit user
# No HEALTHCHECK (trivy DS-0026): a throwaway target that lives for one test run: nothing watches its health
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server procps iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash audit \
 && mkdir -p /run/sshd /home/audit/.ssh \
 && chmod 700 /home/audit/.ssh && chown audit:audit /home/audit/.ssh \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
CMD ["sh", "-c", "install -o audit -g audit -m 600 /key.pub /home/audit/.ssh/authorized_keys && exec /usr/sbin/sshd -D -e"]
