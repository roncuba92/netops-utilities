import os
import datetime
from netmiko import ConnectHandler

class GestorRed:
    def obtener_info_dispositivo(self, ip, usuario, contrasena, secreto):
        return {
            'device_type': 'cisco_ios',
            'host': ip.strip(),
            'username': usuario.strip(),
            'password': contrasena.strip(),
            'secret': secreto.strip(),
        }

    def probar_conexion(self, info_dispositivo):
        with ConnectHandler(**info_dispositivo) as conn:
            return conn.find_prompt()

    def aplicar_cambios(self, info_dispositivo, lista_tareas, callback_log=None):
        registrar = callback_log or (lambda *_: None)
        registrar(">>> INICIANDO CONEXIÓN SSH...")
        hostname_esperado = None
        vlans_esperadas = {}
        with ConnectHandler(**info_dispositivo) as conn:
            conn.enable()
            for tipo_tarea, descripcion_tarea in lista_tareas:
                registrar(f"Procesando: {descripcion_tarea}")
                if tipo_tarea == "HOSTNAME":
                    nuevo_hostname = descripcion_tarea.split(":")[-1].strip()
                    conn.send_config_set([f"hostname {nuevo_hostname}"])
                    conn.base_prompt = nuevo_hostname
                    hostname_esperado = nuevo_hostname
                    registrar(f"✔ Hostname actualizado: {conn.find_prompt()}")
                elif tipo_tarea == "VLAN":
                    try:
                        vlan_id, vlan_nombre = descripcion_tarea.split("VLAN", 1)[1].split(": Nombre", 1)
                        vlan_id, vlan_nombre = vlan_id.strip(), vlan_nombre.strip(" '")
                        conn.send_config_set([f"vlan {vlan_id}", f"name {vlan_nombre}"])
                        vlans_esperadas[vlan_id] = vlan_nombre
                        registrar(f"✔ VLAN {vlan_id} configurada.")
                    except Exception as exc:
                        registrar(f"⚠ Error leyendo tarea: {descripcion_tarea} ({exc})")
            registrar("Guardando en NVRAM (wr mem)...")
            conn.save_config()
            prompt = conn.find_prompt()

            desviaciones = []
            hostname_actual = conn.find_prompt().rstrip("#")
            if hostname_esperado and hostname_actual != hostname_esperado:
                desviaciones.append(f"Hostname esperado '{hostname_esperado}', encontrado '{hostname_actual}'")

            if vlans_esperadas:
                salida_vlans = conn.send_command("show vlan brief")
                for vlan_id, vlan_nombre in vlans_esperadas.items():
                    linea = next((ln for ln in salida_vlans.splitlines() if ln.strip().startswith(vlan_id)), None)
                    if not linea:
                        desviaciones.append(f"VLAN {vlan_id} no existe")
                        continue
                    partes = linea.split()
                    nombre_actual = partes[1] if len(partes) > 1 else ""
                    if nombre_actual.lower() != vlan_nombre.lower():
                        desviaciones.append(f"VLAN {vlan_id} nombre esperado '{vlan_nombre}', encontrado '{nombre_actual}'")

            if desviaciones:
                for desviacion in desviaciones:
                    registrar(f"⚠ Configuración no estándar: {desviacion}")
            else:
                registrar("✔ Validación OK: Configuración aplicada correctamente.")

            return prompt, desviaciones

    def realizar_respaldo(self, info_dispositivo, modo, ip_tftp=None, callback_log=None):
        registrar = callback_log or (lambda *_: None)
        registrar(">>> INICIANDO BACKUP...")
        with ConnectHandler(**info_dispositivo) as conn:
            conn.enable()
            hostname = conn.find_prompt().rstrip("#")
            sello_tiempo = datetime.datetime.now()
            if modo == "Local (PC)":
                os.makedirs("repositorio_backups", exist_ok=True)
                nombre_archivo = f"repositorio_backups/{hostname}_backup_{sello_tiempo:%Y-%m-%d_%H-%M-%S}.txt"
                with open(nombre_archivo, "w", encoding="utf-8") as archivo:
                    archivo.write(conn.send_command("show running-config"))
                return "LOCAL", nombre_archivo
            if not ip_tftp:
                raise ValueError("Falta IP TFTP")
            nombre_archivo = f"{hostname}-{sello_tiempo:%Y%m%d-%H%M}.cfg"
            salida = conn.send_command_timing(f"copy running-config tftp://{ip_tftp}/{nombre_archivo}")
            if "Address or name" in salida: salida += conn.send_command_timing("\n")
            if "Destination filename" in salida: salida += conn.send_command_timing("\n")
            salida_min = salida.lower()
            if any(palabra in salida_min for palabra in ("error", "invalid", "fail", "timed out", "denied")):
                raise Exception(f"Fallo TFTP:\n{salida}")
            if "bytes copied" in salida_min or "ok" in salida_min or "copy complete" in salida_min:
                return "REMOTE", nombre_archivo
            return "REMOTE", nombre_archivo

    def desconectar_dispositivo(self, info_dispositivo, callback_log=None):
        registrar = callback_log or (lambda *_: None)
        registrar(">>> CERRANDO SESIÓN SSH...")
        try:
            with ConnectHandler(**info_dispositivo) as conn:
                conn.disconnect()
            registrar("Sesión cerrada.")
        except Exception as exc:
            registrar(f"No se pudo cerrar sesión: {exc}")
            raise
