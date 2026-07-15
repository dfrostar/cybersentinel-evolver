# Weekly Evolution Loop Scheduler

## Systemd (recommended)

Two files: a service + a timer. The timer triggers weekly; the service runs one evolution cycle.

```bash
cp cs-evolver.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cs-evolver.timer
systemctl status cs-evolver.timer
```

## Manual Cron

```cron
# Every Sunday at 02:00 UTC
0 2 * * * /home/dtfrost/cybersentinel-evolver/scheduler/run_evolve.sh
```

## Behavior

Each cycle:
1. Run `cs-evolver scenarios` — generate fresh threat-feed-grounded scenarios
2. Run `cs-evolver tournament` — pit detectors against full scenario set
3. Run `cs-evolver gap-analysis --type mutations` — identify escaped mutations
4. Run `cs-evolver evolve --weeks 1` — mutate survivors + re-run tournament
5. Run `cs-evolver evolve --weeks 1 --auto-promote` — promote winner
6. Log timestamped success/failure to `/var/log/cs-evolver.log`

## Outputs

- `~/cybersentinel-evolver/data.db` — all results
- `/var/log/cs-evolver.log` — cycle history
