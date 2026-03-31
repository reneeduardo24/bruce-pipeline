# bruce-pipeline

`bruce-pipeline` is an MVP for Raspberry Pi + CasaOS that ingests Bruce RAW Sniffer captures, validates `.pcap/.pcapng` files, deduplicates by SHA256, extracts Wi-Fi metrics with `tshark`, computes IACO, classifies the environment, and publishes persistent JSON, CSV, and HTML outputs.

## Included services

- `bruce-analyzer`: watches `/data/inbox`, processes captures, persists state in SQLite, updates reports, and runs a hook on classification changes.
- `bruce-dashboard`: `nginx:alpine` container that serves the latest generated HTML dashboard on port `8088`.

## Persistent tree

The stack expects this host path:

```text
/srv/bruce-pipeline
├── inbox/
├── processed/pcap/YYYY/MM/DD/
├── quarantine/YYYY/MM/DD/
├── duplicates/YYYY/MM/DD/
├── reports/
│   ├── json/YYYY/MM/DD/
│   ├── csv/YYYY/MM/DD/
│   └── html/
│       ├── YYYY/MM/DD/
│       └── index.html
├── state/
│   ├── active_profile.json
│   └── current_state.json
└── db/
    └── bruce_pipeline.sqlite3
```

## IACO metric

The analyzer calculates:

- `F`: total 802.11 frames
- `B`: unique BSSIDs observed
- `K`: unique Wi-Fi source MACs observed
- `P`: probe request + probe response frames
- `D`: deauthentication + disassociation frames

Normalizations:

```text
NF = min(F/250, 1)
NB = min(B/25, 1)
NK = min(K/30, 1)
NP = min(P/20, 1)
ND = min(D/10, 1)

IACO = 100 * (0.35*NF + 0.20*NB + 0.20*NK + 0.15*NP + 0.10*ND)
```

Classification bands:

- `0-34`: `NORMAL`
- `35-64`: `CONGESTIONADO`
- `65-100`: `CRITICO`

## Local run

```bash
BRUCE_DATA_ROOT=./local-data docker compose up --build -d
```

Then drop a capture into `./local-data/inbox/` and open `http://localhost:8088`.

## Manual test with the real sample

Use `C:\Users\Rene Hernandez\Downloads\raw_2.pcap` only as a host-side example source file for manual testing. It is not a runtime path inside the container.

Example flow:

1. Start the stack.
2. Copy the sample file into the inbox mounted on the host.
3. Wait for the analyzer to move the file into `processed/pcap/YYYY/MM/DD/`.
4. Review `reports/json`, `reports/csv`, `reports/html/index.html`, and `state/current_state.json`.

## CasaOS deployment

1. Let GitHub Actions publish `ghcr.io/reneeduardo24/bruce-pipeline-analyzer`.
2. In CasaOS, open Custom Install and import `docker-compose.casaos.yml`.
3. Make sure `/srv/bruce-pipeline` exists on the Raspberry Pi.
4. Launch the stack and upload `.pcap` files into `/srv/bruce-pipeline/inbox`.

## GitHub Actions + GHCR

The workflow in `.github/workflows/publish.yml` runs tests, builds a multi-arch image for `linux/amd64` and `linux/arm64`, and publishes tags:

- `latest` on `main`
- `sha-*` for each pushed commit
- `vX.Y.Z` for release tags

## Hook behavior

When classification changes, `bruce-analyzer` executes `HOOK_PATH` with these environment variables:

- `BRUCE_OLD_CLASSIFICATION`
- `BRUCE_NEW_CLASSIFICATION`
- `BRUCE_IACO_SCORE`
- `BRUCE_STATE_FILE`
- `BRUCE_SUMMARY_FILE`
- `BRUCE_CAPTURE_SHA256`
- `BRUCE_CAPTURE_PATH`

The default hook appends the transition to `/data/state/hook-events.log`.
