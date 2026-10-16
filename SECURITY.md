# Reporting security issues

trassa runs as `root` on a router and serves a page on the home network, so a weakness in it is
a weakness of the whole network. For a suspected vulnerability, use GitHub's private
vulnerability reporting on this repository, or ask the repository owner for a private contact.
Please do not post exploit details in a public issue.

When sharing diagnostics, remove what identifies your network and its people: the router's
administrator password and SSH keys, the router's public address and KeenDNS name, WireGuard
configurations, device names and MAC addresses in your rules, and DNS answers from the page or
`/tmp/trassa.log`. Do not attach router backups (`tools/router.sh backup`, the `backup/` folder).
A minimal reproduction with sample names and addresses is the most useful.
