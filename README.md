# bruce-pipeline

`bruce-pipeline` es un MVP para Raspberry Pi + CasaOS que ingesta capturas de Bruce RAW Sniffer, valida archivos `.pcap/.pcapng`, deduplica por SHA256, extrae métricas Wi-Fi con `tshark`, calcula IACO, clasifica el entorno y publica salidas persistentes en JSON, CSV y HTML.

## Servicios incluidos

- `bruce-analyzer`: vigila `/data/inbox`, procesa capturas, persiste estado en SQLite, actualiza reportes y ejecuta un hook cuando cambia la clasificación.
- `bruce-dashboard`: contenedor `nginx:alpine` que sirve el dashboard HTML más reciente en el puerto `8088`.

## Árbol persistente

El stack espera esta ruta en el host:

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

## Métrica IACO

El analizador calcula:

- `F`: total de tramas 802.11
- `B`: BSSIDs únicos observados
- `K`: MACs de origen Wi-Fi únicas observadas
- `P`: tramas de probe request + probe response
- `D`: tramas de deauthentication + disassociation

Normalizaciones:

```text
NF = min(F/250, 1)
NB = min(B/25, 1)
NK = min(K/30, 1)
NP = min(P/20, 1)
ND = min(D/10, 1)

IACO = 100 * (0.35*NF + 0.20*NB + 0.20*NK + 0.15*NP + 0.10*ND)
```

Bandas de clasificación:

- `0-34`: `NORMAL`
- `35-64`: `CONGESTIONADO`
- `65-100`: `CRITICO`

## Ejecución local

```bash
BRUCE_DATA_ROOT=./local-data docker compose up --build -d
```

Después, coloca una captura en `./local-data/inbox/` y abre `http://localhost:8088`.

## Despliegue en CasaOS

1. Deja que GitHub Actions publique `ghcr.io/reneeduardo24/bruce-pipeline-analyzer`.
2. En CasaOS, abre Custom Install e importa `docker-compose.casaos.yml`.
3. Asegúrate de que `/srv/bruce-pipeline` exista en la Raspberry Pi.
4. Inicia el stack y sube archivos `.pcap` a `/srv/bruce-pipeline/inbox`.

## GitHub Actions + GHCR

El workflow en `.github/workflows/publish.yml` ejecuta pruebas, construye una imagen multi-arquitectura para `linux/amd64` y `linux/arm64`, y publica tags:

- `latest` en `main`
- `sha-*` para cada commit enviado
- `vX.Y.Z` para tags de versión

## Comportamiento del hook

Cuando cambia la clasificación, `bruce-analyzer` ejecuta `HOOK_PATH` con estas variables de entorno:

- `BRUCE_OLD_CLASSIFICATION`
- `BRUCE_NEW_CLASSIFICATION`
- `BRUCE_IACO_SCORE`
- `BRUCE_STATE_FILE`
- `BRUCE_SUMMARY_FILE`
- `BRUCE_CAPTURE_SHA256`
- `BRUCE_CAPTURE_PATH`

El hook por defecto agrega la transición en `/data/state/hook-events.log`.
