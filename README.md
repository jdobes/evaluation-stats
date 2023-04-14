# evaluation-stats

1. Create local SQLite database with system profiles using gabi

        export GABI_URL="..."
        export GABI_TOKEN="..."
        ./get_sys_profiles.py system.sqlite

2. Run VMaaS with populated database locally
3. Evaluate random sample of 10000 systems

        ./eval_systems.py system.sqlite 10000

4. Example results

        total playbook cves: 816902
        average playbook cves per system: 81.74742319623736
        total manual cves: 81637
        average manual cves per system: 8.169418593015111
        total unfixed cves: 10370212
        average unfixed cves per system: 1037.7476233363354
        total unfixed packages: 1033959
        average unfixed packages per system: 103.46832782948064
        total packages: 8234862
        average packages per system: 824.0630441308916
