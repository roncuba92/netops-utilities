# NetConfigurator (Automatización de Switch Cisco)

Script en Python con interfaz gráfica (CustomTkinter) para configurar hostname y VLANs en un switch Cisco IOS (físico o simulado) usando Netmiko. Permite validar la configuración aplicada, guardar en NVRAM y realizar respaldos locales o vía TFTP.

## Requisitos previos
- Python 3.10 o superior.
- Dependencias: `customtkinter`, `netmiko`.
- Acceso SSH habilitado en el switch y credenciales con modo enable.
- Opcional: servidor TFTP accesible desde el switch (para backup remoto).

## Instalación
```bash
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -e .
```
Si prefieres sin modo editable:
```bash
pip install customtkinter netmiko
```

## Ejecución
```bash
python main.py
```

## Uso rápido (UI)
1. Completa IP, usuario, password y enable; pulsa **Conectar**.
2. Para hostname: escribe el nuevo nombre y pulsa **Agregar**.
3. Para VLANs: ingresa ID (1–4094) y nombre, pulsa **Agregar** tantas como necesites.
4. Las tareas aparecerán en la lista de la derecha; puedes quitar las seleccionadas con **Quitar Seleccionado**.
5. Pulsa **Aplicar Cambios** para enviar la configuración; la app valida hostname y VLANs y muestra desviaciones en los logs/alertas.
6. Respaldo:
   - **Local (PC)**: guarda `show running-config` en `repositorio_backups/`.
   - **Servidor Remoto (TFTP)**: ingresa IP TFTP y pulsa **Guardar en PC/Enviar a TFTP**. La salida del comando de copia se registra.

## Validación y logs
- El backend revisa que el hostname resulte el esperado y que cada VLAN solicitada exista con el nombre indicado; cualquier discrepancia se muestra en los logs y en la alerta de la UI.
- Errores devueltos por el switch (comandos inválidos, VLAN fuera de rango, etc.) se registran y la tarea se marca como desviación.

## Estructura del proyecto
- `main.py`: interfaz gráfica y gestión de tareas encoladas.
- `core.py`: lógica de conexión, aplicación de cambios, validación y backups.
- `pyproject.toml`: metadatos y dependencias del proyecto.

## Notas y buenas prácticas
- Ejecuta la app desde una red con alcance SSH al switch y con la IP del TFTP accesible (si usas backup remoto).
- Recomendado: commits frecuentes con mensajes descriptivos para documentar cambios.
- Puedes añadir capturas de pantalla en este README si las necesitas para la entrega.***
