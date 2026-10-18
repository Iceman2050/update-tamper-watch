"""update-tamper-watch: scheduled poller for vendors' update manifests.

Watches for hash changes on vendor update-manifest/checksum URLs, and
specifically for the tamper-window signature: a change that REVERTS within
minutes, like the UNC7017 campaign against AOMEI Backupper's update servers
(Google Threat Intelligence Group + Mandiant, disclosed Oct 2026).
"""

__version__ = "0.1.0"
