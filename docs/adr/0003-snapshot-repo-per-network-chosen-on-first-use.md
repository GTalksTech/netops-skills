# One snapshot repo per network, its location chosen on first use

Every network-ops skill used to put the snapshot repo in `~/network-snapshots` unless told
otherwise, so users who started Claude Code in a project folder could not tell where their files
went. Now each network has one snapshot repo, kept outside project folders, and the engineer
chooses where it lives the first time a skill needs it. The choice is saved in a user settings
file and every skill, and every scheduled run, finds it the same way through one shared resolver
in `lib/snapshotrepo`. Each run says which repo it used.

It lives outside projects because the network outlives any project that looks at it; because its
configs are sensitive and must not land in a project repo that may be public; and because a
scheduled run has no working directory to find a project from. A project can still name its
network with a small pointer file that holds no data. The script never asks or guesses: when no
repo is set up it stops with a machine-readable error, and the agent asks the engineer.

We rejected a silent fixed default (it is the reason users lost track of their files, and it
picks a location for something sensitive without asking), and a snapshot folder inside each
project (one network would be split across projects, configs would end up in project repos, and
scheduled runs could not find it). Users of the old default are not broken: a first run that
finds `~/network-snapshots/inventory.yaml` adopts that folder, saves it and says so.
