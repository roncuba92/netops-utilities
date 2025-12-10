# netops-utilities (NetConfigurator y AutoVPN)

Este README sirve como referencia breve. Para instalación y uso detallado, revisa los README dentro de cada proyecto.

## Proyectos
- `NetConfigurator/`: app de escritorio (CustomTkinter + Netmiko) para gestionar hostname, VLANs y respaldos en switches Cisco IOS. Más info en `NetConfigurator/README.md`.
- `AutoVPN/`: scripts que generan planes y comandos CLI (FortiGate/Palo Alto) y los aplican por SSH/Netmiko para armar un túnel IPSec. Más info en `AutoVPN/README.md`.

## Dependencias compartidas
- `pyproject.toml`, `uv.lock`: manejo de dependencias (uv). Ambos proyectos usan el mismo entorno virtual en la raíz.
