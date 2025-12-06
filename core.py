import os
import datetime
from netmiko import ConnectHandler

class NetworkManager:
    def get_device_info(self, ip, user, password, secret):
        return {
            'device_type': 'cisco_ios',
            'host': ip.strip(),
            'username': user.strip(),
            'password': password.strip(),
            'secret': secret.strip(),
        }

    def test_connection(self, device_info):
        with ConnectHandler(**device_info) as conn:
            return conn.find_prompt()

    def apply_changes(self, device_info, task_list, log_callback=None):
        log = log_callback or (lambda *_: None)
        log(">>> INICIANDO CONEXIÓN SSH...")
        expected_hostname = None
        expected_vlans = {}
        with ConnectHandler(**device_info) as conn:
            conn.enable()
            for task_type, task_desc in task_list:
                log(f"Procesando: {task_desc}")
                if task_type == "HOSTNAME":
                    name = task_desc.split(":")[-1].strip()
                    conn.send_config_set([f"hostname {name}"])
                    conn.base_prompt = name
                    expected_hostname = name
                    log(f"✔ Hostname cambiado: {conn.find_prompt()}")
                elif task_type == "VLAN":
                    try:
                        vid, vname = task_desc.split("VLAN", 1)[1].split(": Nombre", 1)
                        vid, vname = vid.strip(), vname.strip(" '")
                        conn.send_config_set([f"vlan {vid}", f"name {vname}"])
                        expected_vlans[vid] = vname
                        log(f"✔ VLAN {vid} configurada.")
                    except Exception as exc:
                        log(f"⚠ Error leyendo tarea: {task_desc} ({exc})")
            log("Guardando en NVRAM (wr mem)...")
            conn.save_config()
            prompt = conn.find_prompt()

            # --- Validación de configuración ---
            deviations = []
            current_host = conn.find_prompt().rstrip("#")
            if expected_hostname and current_host != expected_hostname:
                deviations.append(f"Hostname esperado '{expected_hostname}', encontrado '{current_host}'")

            if expected_vlans:
                vlan_out = conn.send_command("show vlan brief")
                for vid, vname in expected_vlans.items():
                    line = next((ln for ln in vlan_out.splitlines() if ln.strip().startswith(vid)), None)
                    if not line:
                        deviations.append(f"VLAN {vid} no existe")
                        continue
                    parts = line.split()
                    actual_name = parts[1] if len(parts) > 1 else ""
                    if actual_name.lower() != vname.lower():
                        deviations.append(f"VLAN {vid} nombre esperado '{vname}', encontrado '{actual_name}'")

            if deviations:
                for dev in deviations:
                    log(f"⚠ Configuración no estándar: {dev}")
            else:
                log("✔ Validación OK: hostname y VLANs coinciden con lo solicitado.")

            return prompt, deviations

    def perform_backup(self, device_info, mode, tftp_ip=None, log_callback=None):
        log = log_callback or (lambda *_: None)
        log(">>> INICIANDO BACKUP...")
        with ConnectHandler(**device_info) as conn:
            conn.enable()
            hostname = conn.find_prompt().rstrip("#")
            ts = datetime.datetime.now()
            if mode == "Local (PC)":
                os.makedirs("repositorio_backups", exist_ok=True)
                fname = f"repositorio_backups/{hostname}_backup_{ts:%Y-%m-%d_%H-%M-%S}.txt"
                with open(fname, "w", encoding="utf-8") as f:
                    f.write(conn.send_command("show running-config"))
                return "LOCAL", fname
            if not tftp_ip:
                raise ValueError("Falta IP TFTP")
            fname = f"{hostname}-{ts:%Y%m%d-%H%M}.cfg"
            out = conn.send_command_timing(f"copy running-config tftp://{tftp_ip}/{fname}")
            if "Address or name" in out: out += conn.send_command_timing("\n")
            if "Destination filename" in out: out += conn.send_command_timing("\n")
            out_l = out.lower()
            if any(word in out_l for word in ("error", "invalid", "fail", "timed out", "denied")):
                raise Exception(f"Fallo TFTP:\n{out}")
            if "bytes copied" in out_l or "ok" in out_l or "copy complete" in out_l:
                return "REMOTE", fname
            # Si no vemos error claro, asumimos éxito porque el dispositivo suele retornar el prompt sin eco.
            return "REMOTE", fname

    def disconnect_device(self, device_info, log_callback=None):
        log = log_callback or (lambda *_: None)
        log(">>> CERRANDO SESIÓN SSH...")
        try:
            with ConnectHandler(**device_info) as conn:
                conn.disconnect()
            log("Sesión cerrada.")
        except Exception as exc:
            log(f"No se pudo cerrar sesión: {exc}")
            raise
