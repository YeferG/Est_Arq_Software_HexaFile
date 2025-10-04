import os
import math
import hashlib
import json
import threading
import zlib
import numpy as np
import pika
from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES


# ==================== Conexión RabbitMQ ====================
def conectar_rabbitmq():
    """Establece conexión con RabbitMQ en localhost."""
    conexion = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    canal = conexion.channel()
    return canal

def publicar_evento(accion):
    """Publica un evento en la cola 'eventos'."""
    canal = conectar_rabbitmq()
    canal.queue_declare(queue='eventos')
    canal.basic_publish(exchange='',
                        routing_key='eventos',
                        body=accion)
    print(f"[MoGriFS] Evento publicado: {accion}")

def publicar_resultado(mensaje):
    """Publica un resultado en la cola 'resultados'."""
    canal = conectar_rabbitmq()
    canal.queue_declare(queue='resultados')
    canal.basic_publish(exchange='',
                        routing_key='resultados',
                        body=mensaje)
    print(f"[MoGriFS] Resultado publicado: {mensaje}")


# ==================== Funciones de Archivo ====================
def cargar_archivo(ruta_archivo):
    try:
        with open(ruta_archivo, 'rb') as archivo:
            return archivo.read()
    except Exception as e:
        messagebox.showerror("Error", f"Error al cargar archivo: {e}")
        return None

def comprimir_datos(contenido_bytes):
    return zlib.compress(contenido_bytes)

def descomprimir_datos(contenido_bytes):
    return zlib.decompress(contenido_bytes)

def bytes_a_imagen_colorida(contenido_bytes, ruta_salida):
    contenido_bytes = comprimir_datos(contenido_bytes)
    alto = math.ceil(math.sqrt(len(contenido_bytes) / 3))
    ancho = math.ceil(len(contenido_bytes) / 3 / alto)
    total_pixels = ancho * alto
    total_bytes_needed = total_pixels * 3

    contenido_bytes += bytes([0]) * (total_bytes_needed - len(contenido_bytes))

    array = np.frombuffer(contenido_bytes, dtype=np.uint8)
    imagen_array = array.reshape((alto, ancho, 3))

    imagen = Image.fromarray(imagen_array, mode='RGB')
    imagen.save(ruta_salida)

def imagen_colorida_a_bytes(ruta_imagen, tamaño_bytes_comprimido):
    Image.MAX_IMAGE_PIXELS = None
    imagen = Image.open(ruta_imagen).convert('RGB')
    arr = np.array(imagen)
    contenido_bytes = arr.flatten()[:tamaño_bytes_comprimido]
    return descomprimir_datos(contenido_bytes)

def generar_log(datos, ruta_salida):
    ruta_log = os.path.splitext(ruta_salida)[0] + ".log"
    with open(ruta_log, 'w') as log:
        json.dump(datos, log, indent=4)
    return ruta_log

def reconstruir_archivo(ruta_log, ruta_imagen, ruta_salida):
    with open(ruta_log, 'r') as log:
        datos_log = json.load(log)

    contenido_recuperado = imagen_colorida_a_bytes(ruta_imagen, datos_log['tamaño_bytes_comprimido'])

    hash_calculado = hashlib.sha256(contenido_recuperado).hexdigest()
    if hash_calculado != datos_log['hash_sha256']:
        raise ValueError("El hash del archivo reconstruido no coincide.")

    ruta_final = os.path.join(ruta_salida, datos_log['nombre'])
    with open(ruta_final, 'wb') as archivo_salida:
        archivo_salida.write(contenido_recuperado)


# ==================== Interfaz Tkinter ====================
def crear_interfaz():
    def seleccionar_archivo():
        archivo = filedialog.askopenfilename(title="Seleccionar archivo")
        if archivo:
            entrada_var.set(archivo)
            salida_var.set(os.path.dirname(archivo))

    def seleccionar_salida():
        carpeta = filedialog.askdirectory(title="Seleccionar carpeta de salida")
        if carpeta:
            salida_var.set(carpeta)

    def hilo_comprimir():
        ruta_archivo = entrada_var.get()
        ruta_salida = salida_var.get()

        if not ruta_archivo or not os.path.isfile(ruta_archivo):
            messagebox.showerror("Error", "Seleccione un archivo válido.")
            return

        if not ruta_salida or not os.path.isdir(ruta_salida):
            messagebox.showerror("Error", "Seleccione una carpeta de salida válida.")
            return

        contenido = cargar_archivo(ruta_archivo)
        if contenido is None:
            return

        nombre_salida = os.path.join(ruta_salida, os.path.basename(ruta_archivo) + ".png")
        contenido_comprimido = comprimir_datos(contenido)
        bytes_a_imagen_colorida(contenido, nombre_salida)

        log_datos = {
            "nombre": os.path.basename(ruta_archivo),
            "extension": os.path.splitext(ruta_archivo)[1],
            "tamaño_original_bytes": len(contenido),
            "tamaño_bytes_comprimido": len(contenido_comprimido),
            "hash_sha256": hashlib.sha256(contenido).hexdigest()
        }
        generar_log(log_datos, nombre_salida)

        reduccion = 100 * (1 - len(contenido_comprimido) / len(contenido))
        messagebox.showinfo("Éxito", f"Archivo comprimido como {nombre_salida}\nReducción: {reduccion:.2f}%")

        # Publicar en RabbitMQ
        publicar_evento("comprimir")
        publicar_resultado("Archivo comprimido")

    def hilo_descomprimir():
        ruta_log = filedialog.askopenfilename(title="Seleccionar archivo log", filetypes=[("Archivos Log", "*.log")])
        ruta_imagen = filedialog.askopenfilename(title="Seleccionar archivo de imagen", filetypes=[("Imágenes PNG", "*.png")])
        ruta_salida = filedialog.askdirectory(title="Seleccionar carpeta de salida")

        if not ruta_log or not ruta_imagen or not ruta_salida:
            messagebox.showerror("Error", "Debe seleccionar un archivo log, una imagen y una carpeta de salida.")
            return

        try:
            reconstruir_archivo(ruta_log, ruta_imagen, ruta_salida)
            messagebox.showinfo("Éxito", "Archivo reconstruido correctamente.")

            # Publicar en RabbitMQ
            publicar_evento("descomprimir")
            publicar_resultado("Archivo descomprimido")

        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error al descomprimir: {e}")
            publicar_resultado(f"Error al descomprimir: {e}")

    def comprimir():
        threading.Thread(target=hilo_comprimir).start()

    def descomprimir():
        threading.Thread(target=hilo_descomprimir).start()

    ventana = TkinterDnD.Tk()
    ventana.title("MoGriFS Integrado")
    ventana.geometry("600x300")
    ventana.resizable(False, False)

    entrada_var = tk.StringVar()
    salida_var = tk.StringVar()

    tk.Label(ventana, text="Archivo de entrada:").pack(pady=5)
    entrada_frame = tk.Frame(ventana)
    entrada_frame.pack(fill="x", padx=10)
    tk.Entry(entrada_frame, textvariable=entrada_var, width=50).pack(side="left", fill="x", expand=True, padx=5)
    tk.Button(entrada_frame, text="Buscar", command=seleccionar_archivo).pack(side="left")

    tk.Label(ventana, text="Carpeta de salida:").pack(pady=5)
    salida_frame = tk.Frame(ventana)
    salida_frame.pack(fill="x", padx=10)
    tk.Entry(salida_frame, textvariable=salida_var, width=50).pack(side="left", fill="x", expand=True, padx=5)
    tk.Button(salida_frame, text="Buscar", command=seleccionar_salida).pack(side="left")

    botones_frame = tk.Frame(ventana)
    botones_frame.pack(pady=20)
    tk.Button(botones_frame, text="Comprimir", command=comprimir, width=15).pack(side="left", padx=10)
    tk.Button(botones_frame, text="Descomprimir", command=descomprimir, width=15).pack(side="left", padx=10)

    ventana.mainloop()

if __name__ == "__main__":
    crear_interfaz()