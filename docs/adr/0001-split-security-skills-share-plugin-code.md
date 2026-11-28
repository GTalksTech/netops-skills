# Split security into separate skills that share network-ops code

The single network-security-check skill did four jobs: CVE matching, config hardening, end of
support, and firewall event analysis. We split it by job: a vulnerability scan first, with a
hardening audit and a lifecycle check as later, separate skills. The pieces they have in common
(reading device facts from saved configs, the priority rules) live once in the network-ops plugin
and are used by every skill that needs them.

We accepted that a skill cannot be copied out of the plugin on its own, even though the Agent
Skills spec prefers self-contained skills, because network-ops skills always ship together and
build on each other, and two copies of the config parsers would drift apart.
