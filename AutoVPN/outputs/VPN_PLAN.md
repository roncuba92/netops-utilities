# Plan de Automatización VPN IPSec (FortiGate ↔ Palo Alto)

## Definición de Parámetros
- Nombre del tunel: fgt-pa-ipsec
- IP WAN FortiGate: 198.51.100.10
- IP WAN Palo Alto: 198.51.100.20
- Red de tunel: 169.255.1.0/30 (FGT 169.255.1.1, PA 169.255.1.2)
- Subredes locales FortiGate: 192.168.1.0/24, 192.168.2.0/24
- Subredes locales Palo Alto: 10.20.1.0/24, 10.20.2.0/24
- Pre-shared key: **SuperSecreto007!**
- IKE: aes256-sha256 DH14 lifetime 28800s (IKEV2)
- IPSec: aes256-sha256 PFS14 lifetime 3600s
- DPD: cada 10s, reintentos 3

## Herramientas/APIs sugeridas
- FortiGate REST (`/api/v2`): crear phase1-interface, phase2-interface, rutas y políticas; soporta token API y HTTPS.
- Palo Alto REST/XML API (`type=config&action=set` o REST v10+): carga en candidate-config y requiere `commit`.
- SSH como respaldo para ambos (bibliotecas Netmiko/Paramiko) para dispositivos sin API habilitada.
- Control de versiones: guardar payloads/plantillas en Git y parametrizar con variables de entorno (psk, IPs, interfaces).

## Pasos de Automatización (alto nivel)
1) Validar parámetros de entrada (IPs válidas, subred de tunel /30, PSK no vacía).
2) FortiGate: crear Phase1 con peer 198.51.100.20, PSK y propuestas; habilitar DPD/NAT-T.
3) FortiGate: crear Phase2 con selectores 192.168.1.0/24 → 10.20.1.0/24 (+3 selectores adicionales), PFS y lifetime.
4) FortiGate: asignar IP 169.255.1.1 al interfaz del tunel, rutas estáticas hacia 10.20.1.0/24 (+1 rutas) y política de firewall (sin NAT) usando objetos/grupos y servicios permitidos.
5) Palo Alto: definir perfiles IKE/IPSec, gateway remoto 198.51.100.10, tunel fgt-pa-ipsec, interfaz 169.255.1.0/30 IP 169.255.1.2.
6) Palo Alto: agregar el tunel al virtual-router, crear rutas a 192.168.1.0/24 (+1 rutas) vía 169.255.1.1, y regla de seguridad permitiendo el tráfico.
7) Publicar/commit: `execute vpn tunnel up` o `diagnose vpn ike restart` en FGT si se requiere; `commit` en Palo Alto.
8) Validar SAs e intercambio de tráfico (pings entre subredes, trazas y monitoreo de logs).

## Consideraciones y Desafíos
- Habilitar NAT-T/keepalive si alguno de los extremos está detrás de NAT.
- Sincronizar hora/NTP para evitar fallas de autenticación por drift de reloj.
- Alinear propuesta IKE/ESP y lifetimes en ambos extremos; cualquier discrepancia levanta fase1 pero no fase2.
- MTU/MSS: ajustar MSS en borde si hay fragmentación; considerar ip-frag en Palo Alto.
- DPD/keepalive: balancear intervalos para evitar falsos positivos en enlaces inestables.
- Zones: en Palo Alto, colocar el `tunnel` en zona dedicada y ajustar políticas desde/hacia esa zona.
- Rutas y zonas: validar que las rutas a subredes remotas usan el tunel y que las políticas permiten ambos sentidos.
- Seguridad: rotar PSK y guardar secretos fuera del repo (variables de entorno o vault).
- Observabilidad: habilitar logs de tráfico y eventos de VPN en ambos dispositivos.
- FortiGate: usar objetos/grupos por subred y grupo de servicios para limitar el alcance del tunel.

## Validación y Alertas
- FortiGate: `get vpn ipsec tunnel summary`, `diagnose vpn ike gateway list`, `diagnose debug application ike -1`.
- Palo Alto: `show vpn ike-sa`, `show vpn ipsec-sa`, `test vpn ipsec-sa tunnel fgt-pa-ipsec`.
- Probar tráfico real: ping desde 192.168.1.0 hacia 10.20.1.0 y viceversa.
- Alertas: suscribir syslog/SNMP/REST a un sistema externo; disparar alarma si SA baja o si hay renegociaciones frecuentes.

## Artefactos generados (opcional en Git)
- `outputs/fortigate_payload.json`: payload listo para `/api/v2/cmdb/...` (ver archivo, no se embebe aquí).
- `outputs/paloalto_commands.txt`: comandos `set` para candidate-config (ver archivo).
- `outputs/VPN_PLAN.md`: este plan.
- `deploy_vpn.py`: aplica payloads/comandos en los equipos (FortiGate REST, Palo Alto SSH).

Separación de Configuración y Documentación: Se generan archivos separados para aislar configuración (payloads/comandos reutilizables), documentación (trazabilidad/auditoría) y validación (scripts), reduciendo riesgo de errores al aplicar cambios y permitiendo versionar cada artefacto por separado.
