# AutoVPN-API (FortiGate por API + Palo Alto por API)

Proyecto paralelo a `AutoVPN-SSH` que aplica la VPN FortiGate ↔ Palo Alto usando la API REST de ambos equipos. Reutiliza el mismo `vpn_config.json`. La planificación completa está en `../VPN_PLAN.md`.

## Estructura
- `vpn_config.json`: parámetros únicos (IP WAN, túnel /30, subredes locales, PSK, propuestas, servicios/apps, interfaces).
- `vpn_api_templates.py`: validación de config y generación de payloads Forti y Palo.
- `deploy_vpn.py`: genera artefactos y aplica (Forti vía API, Palo Alto vía API + commit).
- `outputs/`: se crea al ejecutar; guarda payloads y plan.

## Requisitos
- Python 3.10+, paquetes `requests` y `netmiko`.
- Token de API Forti (`Authorization: Bearer ...`) con permisos de escritura en el VDOM.
- Acceso SSH a Palo Alto (admin/commit).

## Uso rápido
1) Edita parámetros en `vpn_config.json`.
2) Solo generar artefactos:
   ```bash
   python3 AutoVPN-API/deploy_vpn.py --config AutoVPN-API/vpn_config.json --fortigate-host 10.24.133.202 --fortigate-token <TOKEN> --paloalto-host <PA_IP> --paloalto-api-key <PA_KEY> --dry-run
   ```
3) Aplicar Forti (API) + Palo (SSH):
   ```bash
  python3 AutoVPN-API/deploy_vpn.py \
    --config AutoVPN-API/vpn_config.json \
    --fortigate-host 10.24.133.202 --fortigate-token <TOKEN> \
    --paloalto-host <PA_IP> --paloalto-api-key <PA_KEY> [--paloalto-timeout 90]
   ```
   Añade `--skip-paloalto` si solo quieres Forti. Usa `--fortigate-verify`/`--paloalto-verify` si tienes certificados válidos y quieres validar TLS. Ajusta `--paloalto-timeout` si el commit demora más de ~60s.

Artefactos generados en `outputs/`:
- `fortigate_payloads.json`: Phase1/2, interfaz, objetos, políticas y rutas para la API Forti.
- `paloalto_payloads.json`: payloads y xpaths para la API de Palo Alto.
- `plan.md`: resumen de parámetros y pasos.

## Notas rápidas
- La planificación de parámetros y consideraciones de lab está en `../VPN_PLAN.md`.
- La aplicación en Forti es idempotente: usa `PUT` y cae a `POST` si no existe; políticas/rutas se actualizan si ya hay una con el mismo nombre/destino.
- Palo Alto usa API XML (`type=config`) con `set` y `commit`; crea/actualiza perfiles, gateway IKE, túnel, proxy-id, rutas, zona, objetos y reglas.
- Si tienes varias subredes, se crean múltiples Phase2/Proxy-ID.
- El gateway de las rutas en Forti usa `fortigate_static_gateway` si está definido, de lo contrario la IP de túnel de Palo (`paloalto_tunnel_ip`).
