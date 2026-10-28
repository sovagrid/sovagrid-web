FROM caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f

# The upstream binary carries cap_net_bind_service. This copy has no file
# capability, allowing cap_drop: ALL and an unprivileged user on high ports.
RUN cp /usr/bin/caddy /usr/local/bin/caddy-rootless && chmod 0755 /usr/local/bin/caddy-rootless

COPY deploy/Caddyfile.container /etc/caddy/Caddyfile
COPY index.html app.js browser-ssh.js files.js amnezia.js process-inventory.js container-logs.js container-control.js container-alerts.js filesystem-alerts.js filesystem-alerts.css service-control.js telegram.js monitoring.js inode.js public-web.js local-web.js journal.js maintenance.js theme.js styles.css theme.css public-web.css manifest.webmanifest sw.js legal.html legal.css LICENSE ATTRIBUTION.md NOTICE users.js access.js users.css backups.js backups-restore.js backups.css host-backups.js host-backups.css checks.js checks.css /srv/
COPY install.js install.css /srv/
COPY icons /srv/icons
COPY vendor /srv/vendor

USER 10002:10002
ENTRYPOINT ["/usr/local/bin/caddy-rootless"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
