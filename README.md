# Cisco Challenge (NetConfigurator y AutoVPN)

Este README sirve como referencia breve. Para instalación y uso detallado, revisa los README dentro de cada proyecto.

## Proyectos
- `NetConfigurator/`: app de escritorio (CustomTkinter + Netmiko) para gestionar hostname, VLANs y respaldos en switches Cisco IOS. Más info en `NetConfigurator/README.md`.
- `AutoVPN/`: script que genera planes y payloads para automatizar un túnel IPSec entre FortiGate y Palo Alto. Más info en `AutoVPN/README.md`.

## Dependencias compartidas
- `pyproject.toml`, `uv.lock`: manejo de dependencias (uv). Ambos proyectos usan el mismo entorno virtual en la raíz.
