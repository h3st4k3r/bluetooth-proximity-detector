# Detector proximidad dispositivos Bluetooth

Este proyecto es una aplicación de Python que utiliza la biblioteca `bleak` para detectar dispositivos Bluetooth cercanos y estimar su distancia del receptor utilizando la intensidad de la señal recibida (RSSI).

![Detección real](https://blog.masalladelfirewall.com/wp-content/uploads/2023/12/Deteccion-bluetooth-cercanos-1024x551.png)

## Características

- Escaneo de dispositivos Bluetooth cercanos.
- Cálculo de la distancia estimada basada en RSSI.
- Representación gráfica de dispositivos y su distancia en una interfaz gráfica de usuario (GUI).
- Posibilidad de acercar y alejar la visualización.

## Requisitos

Para ejecutar este proyecto, necesitarás:

- Python 3.7 o superior.
- `bleak` para la comunicación Bluetooth.
- `tkinter` para la GUI.

## Instalación

Asegúrate de tener Python instalado en tu sistema. Luego, instala las dependencias con pip:

pip install bleak
pip install tk

## Uso

Para iniciar la aplicación, ejecuta el siguiente comando en tu terminal:

python detector_bluetooth.py

Usa el botón "Escanear dispositivos" para iniciar el proceso de detección. La interfaz mostrará los dispositivos detectados junto con su distancia estimada.

##Cálculo de Distancia

El cálculo de la distancia se realiza utilizando la siguiente fórmula:

distancia = 10 ^ ((RSSI_REF - RSSI) / (10 * PATH_LOSS_EXPONENT))

Donde `RSSI_REF` es el RSSI medido a un metro de distancia, y `PATH_LOSS_EXPONENT` es el exponente de pérdida de trayectoria, que depende del entorno.

## Contribuciones

Las contribuciones a este proyecto son bienvenidas. De la comunidad para la comunidad.
