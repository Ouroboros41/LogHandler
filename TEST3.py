import os
import time
import logging
from datetime import datetime
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

class LogHandler(FileSystemEventHandler):
    def __init__(self, log_file, block_time=6):
        self.log_file = log_file
        self.last_error_timestamp = 0  # Marca de tiempo del último error procesado
        self.file_position = 0  # Puntero al final del archivo
        self.cooldown_time = block_time  # Segundos de bloqueo
        self.error_block_until = 0  # Tiempo hasta el cual ignorar errores

    def on_modified(self, event):
        if event.src_path == self.log_file and os.path.isfile(self.log_file):
            self.check_for_errors()

    def check_for_errors(self):
        """Revisa el log en busca del primer error y aplica un bloqueo temporal tras detectarlo."""
        try:
            with open(self.log_file, "r") as file:
                file.seek(self.file_position)  # Ir a la última posición leída
                new_lines = file.readlines()  # Leer solo nuevas líneas
                self.file_position = file.tell()  # Actualizar posición

                for line in new_lines:
                    current_time = time.time()

                    # Ignorar errores si aún estamos en el tiempo de bloqueo
                    if current_time < self.error_block_until:
                        continue

                    # Detectar la palabra clave "|ERROR|"
                    if "|ERROR|" in line:
                        timestamp_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                        if timestamp_match:
                            timestamp_str = timestamp_match.group(1)
                            try:
                                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").timestamp()
                                # Procesar el error si es nuevo y posterior al inicio del script
                                if timestamp > self.last_error_timestamp and timestamp > start_time:
                                    logging.info(f"Error detectado: {line.strip()}")
                                    self.last_error_timestamp = timestamp
                                    restart_service(service_name)

                                    # Establecer un tiempo de bloqueo 
                                    self.error_block_until = current_time + self.cooldown_time
                                    break
                            except ValueError:
                                logging.error(f"Formato de fecha invalido: {timestamp_str}")
        except (FileNotFoundError, IOError) as e:
            logging.error(f"Error al acceder al archivo {self.log_file}: {e}")
        except Exception as e:
            logging.exception(f"Error inesperado: {e}")

def restart_service(service_name):
    """Función para reiniciar el servicio."""
    try:
        subprocess.run(["powershell", "-Command", f"Restart-Service -Name '{service_name}'"], check=True)
        logging.info(f"Servicio '{service_name}' reiniciado con éxito.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al reiniciar el servicio: {e}")

def get_log_filename():
    """Obtiene el nombre del archivo log actual en formato yyyy-mm-dd.log."""
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

def monitor_log_file():
    """Monitorea el archivo de log y reinicia el servicio si es necesario."""
    current_log_file = get_log_filename()
    if not current_log_file:
        return

    event_handler = LogHandler(current_log_file, block_time=6)  # segundos de bloqueo ajustables
    observer = Observer()
    observer.schedule(event_handler, log_directory, recursive=False)

    observer.start()
    logging.info("Monitorización iniciada.")

    try:
        while True:
            time.sleep(1)
            # Validar si el archivo de log ha cambiado (nueva fecha)
            expected_log_file = get_log_filename()
            if expected_log_file != current_log_file:
                logging.info(f"Cambio de archivo de log detectado. Nuevo archivo: {expected_log_file}")
                if not expected_log_file:
                    logging.error("No se encontró un archivo de log para el nuevo dia. Continuando monitorización del archivo actual.")
                    continue

                # Actualizar el archivo de log monitorizado
                observer.unschedule_all()
                event_handler = LogHandler(expected_log_file, block_time=6)
                observer.schedule(event_handler, log_directory, recursive=False)
                current_log_file = expected_log_file
                logging.info(f"Monitorización actualizada al archivo de log: {current_log_file}")

    except KeyboardInterrupt:
        logging.info("Monitorización detenida manualmente.")
    finally:
        observer.stop()
        observer.join()

if __name__ == "__main__":
    monitor_log_file()
