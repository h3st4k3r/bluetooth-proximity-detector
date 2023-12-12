# @author Luis Diago de Aguilar aka h3st4k3r
import asyncio
from bleak import discover
import tkinter as tk
from math import pi, cos, sin
import random

# Calibrar valores medidos según entorno
RSSI_REF = -60  
PATH_LOSS_EXPONENT = 2  

async def buscar_dispositivos_bluetooth():
    dispositivos = await discover()
    return [(dispositivo.address, dispositivo.name or "Desconocido", dispositivo.rssi) for dispositivo in dispositivos]

def calcular_distancia(rssi):
    ratio_db = RSSI_REF - rssi
    ratio_linear = 10 ** (ratio_db / (10 * PATH_LOSS_EXPONENT))
    return ratio_linear

def generar_color_unico():
    return f"#{random.randint(0, 255):02x}{random.randint(0, 255):02x}{random.randint(0, 255):02x}"

def actualizar_interfaz(canvas, lista, dispositivos, x_centro, y_centro, escala):
    canvas.delete("all")
    lista.delete(0, tk.END)  
    
    canvas.create_oval(x_centro - 5, y_centro - 5, x_centro + 5, y_centro + 5, fill="red")
    canvas.create_text(x_centro, y_centro - 10, text="You", fill="red")

    for dispositivo in dispositivos:
        direccion, nombre, rssi = dispositivo
        distancia = calcular_distancia(rssi)
        color = generar_color_unico()
        angle = random.uniform(0, 2 * pi)
        x_pos = x_centro + distancia * escala * cos(angle)
        y_pos = y_centro + distancia * escala * sin(angle)
        
        canvas.create_line(x_centro, y_centro, x_pos, y_pos, fill=color)
        
        canvas.create_oval(x_pos - 3, y_pos - 3, x_pos + 3, y_pos + 3, outline=color, fill=color)
        
        info = f"{nombre}: {distancia:.2f} m (RSSI: {rssi} dBm)"
        lista.insert(tk.END, info)
        
        canvas.create_text(x_pos, y_pos, text=f"{nombre} ({distancia:.2f} m)", fill=color, anchor="center")

async def actualizar_async(canvas, lista, x_centro, y_centro, escala):
    dispositivos = await buscar_dispositivos_bluetooth()
    actualizar_interfaz(canvas, lista, dispositivos, x_centro, y_centro, escala)

def on_actualizar_click(canvas, lista, x_centro, y_centro, escala):
    asyncio.run(actualizar_async(canvas, lista, x_centro, y_centro, escala))

def zoom_in(canvas, x_centro, y_centro, escala):
    escala_nueva = escala * 1.2
    canvas.scale("all", x_centro, y_centro, 1.2, 1.2)
    return escala_nueva

def zoom_out(canvas, x_centro, y_centro, escala):
    escala_nueva = escala / 1.2
    canvas.scale("all", x_centro, y_centro, 0.8, 0.8)
    return escala_nueva

def main():
    ventana = tk.Tk()
    ventana.title("Detector Bluetooth by h3st4k3r")
    ventana.geometry("800x600")

    frame = tk.Frame(ventana)
    frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    canvas = tk.Canvas(frame, width=800, height=600)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    lista = tk.Listbox(frame)
    lista.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    x_centro, y_centro = 400, 300  
    escala = 2  

    boton_escanear = tk.Button(ventana, text="Escanear dispositivos", command=lambda: on_actualizar_click(canvas, lista, x_centro, y_centro, escala))
    boton_escanear.pack(side=tk.BOTTOM)

    boton_zoom_in = tk.Button(ventana, text="+", command=lambda: zoom_in(canvas, x_centro, y_centro, escala))
    boton_zoom_in.pack(side=tk.BOTTOM)

    boton_zoom_out = tk.Button(ventana, text="-", command=lambda: zoom_out(canvas, x_centro, y_centro, escala))
    boton_zoom_out.pack(side=tk.BOTTOM)

    ventana.mainloop()

if __name__ == "__main__":
    main()
