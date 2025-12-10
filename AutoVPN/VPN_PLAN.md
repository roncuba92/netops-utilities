# Planificación y Evaluación de AutoVPN (FortiGate ↔ Palo Alto)

Documento que resume los parámetros, herramientas y criterios de validación para la automatización de la VPN IPSec entre FortiGate y Palo Alto. Los scripts viven en `AutoVPN-SSH/` (Netmiko) y `AutoVPN-API/` (API REST/XML).

## Definición de Parámetros (Ejemplo para este laboratorio)
- Red de túnel: `169.255.1.0/30`  
  - IP FortiGate: `169.255.1.1`  
  - IP Palo Alto: `169.255.1.2`
- WAN: FortiGate `198.51.100.10`, Palo Alto `203.0.113.10`
- LAN: FortiGate `192.168.10.0/24`, Palo Alto `10.20.10.0/24`
- PSK: `SuperSecreto007!`
- Propuestas Fase 1: `DES/SHA1/DH2`, IKEv2, lifetime 28800s
- Propuestas Fase 2: `DES/SHA1/PFS2`, lifetime 3600s
- Interfaces clave: Forti WAN `port1`, inside `port3`; PA túnel `tunnel.10`, zona `vpn-network`, VR `default`, IKE `ethernet1/1`, inside `ethernet1/2`

### Nota de Laboratorio
La imagen virtual de FortiGate del laboratorio solo soporta cifrados básicos (perfil low-encryption). Se fuerza el uso de `DES/SHA1/Group2` en Fase 1/2 en vez de `AES256/SHA256` para asegurar compatibilidad con Palo Alto. En entornos productivos cambiar a suites fuertes y habilitar `strong-crypto` en ambos extremos.

## Herramientas y APIs
- SSH/CLI: Netmiko (`device_type` `fortinet` y `paloalto_panos`) para aplicar plantillas en `AutoVPN-SSH/`.
- API REST FortiOS: `requests` contra `/api/v2` (JSON, token Bearer) para crear objetos, interfaces, políticas y rutas en `AutoVPN-API/`.
- API Palo Alto: `requests` contra `/api/` usando XML + XPath. Diferencia clave: FortiOS es REST/JSON, mientras Palo Alto usa XML con operaciones `set/edit/commit` y rutas XPath exactas.

## Pasos de Automatización (flujo lógico)
1) **Interfaces**: crear la interfaz de túnel y habilitar `ping`/perfiles de gestión (PA) y bind a zona/VR.  
2) **Objetos**: direcciones locales/remotas y grupos para ambos lados.  
3) **Crypto Profiles**: perfiles IKE (Fase 1)/IPSec (Fase 2) (propuestas, DH/PFS, lifetimes) y gateway/peer.  
4) **Políticas**: reglas de seguridad/ACL permitiendo tráfico entre grupos locales/remotos con servicios/apps declaradas.  
5) **Rutas**: rutas estáticas hacia las subredes remotas apuntando al túnel o interfaz virtual.

## Desafíos Relevantes
- Armado de payloads XML en Palo Alto: rutas XPath exactas y orden estricto `set` → `commit`. Se requiere limpiar (`delete`) entradas previas o el `commit` falla por referencias colgantes.
- Normalización de datos: un solo `vpn_config.json` debe mapear a Forti (REST/JSON) y Palo (XML). Hubo varias iteraciones para alinear nombres (proxy-id vs selectors), lifetimes y servicios para que ambos lados acepten el mismo set de valores.
- Sincronía de propuestas/selector-proxy-id: cualquier desviación en proposal, DH/PFS o redes rompe la negociación y deja SAs huérfanas. También hay que alinear los timers (lifetime, DPD) para evitar renegociaciones fuera de fase.
- NAT-T y MTU/MSS: en enlaces con NAT, activar NAT-T en Forti y ajustar MSS/MTU (o TCP clamping) evita fragmentación. Sin esto, el túnel “sube” pero el tráfico se pierde.
- Orden de aplicación: en Forti se puede aplicar en línea, pero en Palo Alto hay que crear objetos, atarlos a zona/VR, y recién luego `commit`. Si se crea el túnel antes que la interfaz/VR, el commit puede rechazar la config.
- Certificados/API: muchas pruebas fallaron por certificados self-signed. En lab se desactiva verify, pero en producción se debe cargar el CA o usar certificados válidos.
- Manejo de sesiones/locks: el commit de Palo Alto es exclusivo; si hay un lock o job en curso, la API responde `in-progress`. Se debe reintentar o limpiar el lock antes de automatizar.
- Duplicados y limpieza: recrear objetos con el mismo nombre en Palo exige borrar primero; en Forti un PUT/POST puede fallar si ya existe o si hay dependencias. Las funciones de “upsert” se añadieron para evitar residuos.
- Validación y pruebas: se probaron pings desde IP de túnel y desde LAN. Algunos labs bloquean ICMP por políticas existentes; hay que abrir servicios/apps mínimas (ICMP, HTTPS/SSH) para validar end-to-end.
- Multi-vdom/vsys: en despliegues con VDOM/VSYS, todos los XPath y parámetros `vdom` deben ser coherentes. Olvidar el VDOM correcto hace que los objetos se creen, pero en el contexto equivocado y el túnel no enruta.

## Validación (teórica)
- **Estado de túneles**:  
  - Forti: `api/v2/monitor/vpn/ipsec` o `get vpn ipsec tunnel summary`.  
  - Palo Alto: `show vpn ike-sa gateway <nombre>` y `show vpn ipsec-sa tunnel <nombre>`.
- **Pruebas de conectividad**: pings iniciados desde la IP de túnel (o desde subred LAN si la API lo permite). Éxito = respuestas ICMP o estado IKE/IPSec en `up/established`.
- **Reporte**: scripts de verificación imprimen `VPN STATUS: UP/DOWN` y retornan código de salida distinto de cero al fallar, apto para CI/alertas.
