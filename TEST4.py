import os
import time
import logging
from datetime import datetime
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess
import glob
import re

# Configuración de log
logging.basicConfig(filename="service_restart_log.txt", level=logging.INFO,
                    format="%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

log_directory = r"C:/Program Files/MiningTag/MT Remote Service/production/logs"
service_name = "MT Remote Service"
start_time = datetime.now().timestamp()
MAX_RESTARTS_PER_HOUR = 5
restart_attempts = deque(maxlen=MAX_RESTARTS_PER_HOUR)
MIN_TIME_BETWEEN_RESTARTS = 120  # Tiempo mínimo entre reinicios (segundos)
last_restart_time = 0  # Última marca de tiempo de reinicio


def get_service_status(service_name):
    """Obtiene el estado del servicio usando PowerShell."""
    try:
        result = subprocess.run(
            ["powershell", "-Command", f"(Get-Service -Name '{service_name}').Status"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al obtener estado del servicio: {e}")
        return None

def start_service(service_name):
    """Inicia el servicio si está detenido."""
    try:
        subprocess.run(["powershell", "-Command", f"Start-Service -Name '{service_name}'"], check=True)
        logging.info(f"Servicio '{service_name}' iniciado con éxito.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al iniciar el servicio: {e}")

def check_and_start_service():
    """Verifica si el servicio está detenido y lo inicia si es necesario."""
    status = get_service_status(service_name)
    if status == "Stopped":
        logging.info(f"El servicio '{service_name}' está detenido. Intentando iniciarlo...")
        start_service(service_name)
    elif status == "Running":
        logging.info(f"El servicio '{service_name}' ya está en ejecución.")
    else:
        logging.warning(f"No se pudo determinar el estado del servicio '{service_name}'.")

class LogHandler(FileSystemEventHandler):
    def __init__(self, log_file, block_time=10):
        self.log_file = log_file
        self.last_error_timestamp = 0
        self.file_position = 0
        self.cooldown_time = block_time
        self.error_block_until = 0

    def on_modified(self, event):
        if event.src_path == self.log_file and os.path.isfile(self.log_file):
            self.check_for_errors()

    def check_for_errors(self):
        try:
            with open(self.log_file, "r") as file:
                file.seek(self.file_position)
                new_lines = file.readlines()
                self.file_position = file.tell()

                for line in new_lines:
                    current_time = time.time()
                    if current_time < self.error_block_until:
                        continue
                    if "|ERROR|" in line:
                        timestamp_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                        if timestamp_match:
                            timestamp_str = timestamp_match.group(1)
                            try:
                                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").timestamp()
                                if timestamp > self.last_error_timestamp and timestamp > start_time:
                                    logging.info(f"Error detectado: {line.strip()}")
                                    self.last_error_timestamp = timestamp
                                    restart_service(service_name)
                                    self.error_block_until = current_time + self.cooldown_time
                                    break
                            except ValueError:
                                logging.error(f"Formato de fecha inválido: {timestamp_str}")
        except Exception as e:
            logging.exception(f"Error inesperado: {e}")

def restart_service(service_name):
    """Reinicia el servicio si es necesario."""
    global last_restart_time
    current_time = time.time()
    
    if current_time - last_restart_time < MIN_TIME_BETWEEN_RESTARTS:
        logging.warning("Reinicio evitado por límite de tiempo mínimo entre reinicios.")
        return
    if len(restart_attempts) >= MAX_RESTARTS_PER_HOUR:
        logging.warning("Límite de reinicios alcanzado. No se reiniciará el servicio.")
        return
    try:
        subprocess.run(["powershell", "-Command", f"Restart-Service -Name '{service_name}'"], check=True)
        logging.info(f"Servicio '{service_name}' reiniciado con éxito.")
        restart_attempts.append(current_time)
        last_restart_time = current_time
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al reiniciar el servicio: {e}")

def monitor_log_file():
    check_and_start_service()
    current_log_file = get_log_filename()
    if not current_log_file:
        return
    event_handler = LogHandler(current_log_file, block_time=10)
    observer = Observer()
    observer.schedule(event_handler, log_directory, recursive=False)
    observer.start()
    logging.info("Monitorización iniciada.")
    try:
        while True:
            time.sleep(1)
            expected_log_file = get_log_filename()
            if expected_log_file != current_log_file:
                logging.info(f"Cambio de log detectado: {expected_log_file}")
                observer.unschedule_all()
                event_handler = LogHandler(expected_log_file, block_time=10)
                observer.schedule(event_handler, log_directory, recursive=False)
                current_log_file = expected_log_file
    except KeyboardInterrupt:
        logging.info("Monitorización detenida manualmente.")
    finally:
        observer.stop()
        observer.join()

def get_log_filename():
    current_date = datetime.now().strftime("%Y-%m-%d")
    log_filename = f"{current_date}.log"
    log_filepath = os.path.join(log_directory, log_filename)
    if not os.path.exists(log_filepath):
        log_files = glob.glob(os.path.join(log_directory, "*.log"))
        if log_files:
            log_filepath = max(log_files, key=os.path.getctime)
        else:
            logging.error("No se encontraron archivos de log.")
            return None
    return log_filepath

if __name__ == "__main__":
    monitor_log_file()
