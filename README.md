# bruce-pipeline

`bruce-pipeline` es un MVP para Raspberry Pi + CasaOS que ingesta capturas de Bruce RAW Sniffer, valida archivos `.pcap/.pcapng`, deduplica por SHA256, extrae métricas Wi-Fi con `tshark`, calcula IACO, clasifica el entorno, genera reportes persistentes en JSON/CSV/HTML y activa un hook real por Telegram cuando cambia la clasificación.

## Servicios incluidos

- `bruce-analyzer`: vigila `/data/inbox`, procesa capturas, persiste estado en SQLite, actualiza reportes y ejecuta un hook cuando cambia la clasificación.
- `bruce-dashboard`: contenedor `nginx:alpine` que sirve el dashboard HTML más reciente en el puerto `8088`.

## Flujo actualizado

1. `bruce-analyzer` espera archivos estables en `/data/inbox`.
2. Valida el `.pcap` o `.pcapng`, calcula SHA256 y detecta duplicados en SQLite.
3. Extrae métricas con `tshark`, calcula IACO y clasifica el entorno como `NORMAL`, `CONGESTIONADO` o `CRITICO`.
4. Publica salidas persistentes en `reports/json`, `reports/csv` y `reports/html`.
5. `bruce-dashboard` expone el HTML más reciente en español.
6. Si la clasificación cambia, el hook registra el evento y puede enviar una notificación por Telegram.

## Dashboard en español

- El placeholder inicial y el reporte HTML final quedan completamente en español.
- El dashboard incorpora la leyenda académica visible: `Proyecto realizado por René Eduardo Hernández Estrella para la Maestría en Ciencias de la Ingeniería, materia Redes.`
- Se mantiene intacto el flujo actual de análisis, generación de reportes y publicación por `nginx:alpine`.

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

Si quieres activar Telegram localmente, exporta antes estas variables:

```bash
export TELEGRAM_ENABLED=true
export TELEGRAM_BOT_TOKEN="tu_token"
export TELEGRAM_CHAT_ID="tu_chat_id"
```

Después, coloca una captura en `./local-data/inbox/` y abre `http://localhost:8088`.

## Despliegue en CasaOS

1. Deja que GitHub Actions publique `ghcr.io/reneeduardo24/bruce-pipeline-analyzer`.
2. En CasaOS, abre Custom Install e importa `docker-compose.casaos.yml`.
3. Asegúrate de que `/srv/bruce-pipeline` exista en la Raspberry Pi.
4. Configura estas variables del servicio `bruce-analyzer` en CasaOS:

```text
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=<token-del-bot>
TELEGRAM_CHAT_ID=<chat-id-destino>
```

5. Inicia el stack y sube archivos `.pcap` a `/srv/bruce-pipeline/inbox`.

Si no deseas notificaciones, deja `TELEGRAM_ENABLED=false` o conserva vacías las otras dos variables.

## GitHub Actions + GHCR

El workflow en `.github/workflows/publish.yml` ejecuta pruebas, construye una imagen multi-arquitectura para `linux/amd64` y `linux/arm64`, y publica tags:

- `latest` en `main`
- `sha-*` para cada commit enviado
- `vX.Y.Z` para tags de versión

## Actuador por Telegram

El hook `hooks/on_state_change.sh` sigue registrando localmente cada cambio en `/data/state/hook-events.log`, pero ahora también puede actuar como notificador real por Telegram.

Variables requeridas:

- `TELEGRAM_ENABLED`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Política de notificación:

- Solo se envía mensaje cuando la clasificación cambia.
- Si el sistema pasa de `NONE` a una clasificación válida, sí se notifica.
- Si la clasificación no cambia, no se envía mensaje repetido.
- Si Telegram falla, el error queda registrado y el pipeline principal sigue procesando el `.pcap`.

Contenido del mensaje enviado:

- clasificación anterior
- nueva clasificación
- score IACO
- nombre del archivo procesado
- SHA256
- fecha y hora de procesamiento

## Comportamiento del hook

Cuando cambia la clasificación, `bruce-analyzer` ejecuta `HOOK_PATH` con estas variables de entorno:

- `BRUCE_OLD_CLASSIFICATION`
- `BRUCE_NEW_CLASSIFICATION`
- `BRUCE_IACO_SCORE`
- `BRUCE_CAPTURE_NAME`
- `BRUCE_STATE_FILE`
- `BRUCE_SUMMARY_FILE`
- `BRUCE_CAPTURE_SHA256`
- `BRUCE_CAPTURE_PATH`
- `BRUCE_PROCESSED_AT`

Si Telegram no está configurado o `TELEGRAM_ENABLED` no está activo, el hook solo registra localmente y no rompe el pipeline.
