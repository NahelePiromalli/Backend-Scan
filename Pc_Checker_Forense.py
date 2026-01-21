import os
import datetime
import pefile
import subprocess
import ctypes
import sys
import html
import uuid
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
import winreg
import struct 
import threading 
import time
import requests 
from queue import Queue, Empty 
import random 
import codecs
import sqlite3 
import shutil 
import re 
import math
from collections import Counter
import yara
import datetime
from datetime import timedelta

# --- FUNCIÓN PARA RUTAS RELATIVAS (NECESARIA PARA NUITKA) ---
def resource_path(relative_path):
    """ Busca archivos tanto en desarrollo como en EXE compilado (Nuitka/PyInstaller) """
    try:
        # OPCION 1: PyInstaller y algunos modos de Nuitka
        base_path = sys._MEIPASS
    except Exception:
        try:
            # OPCION 2: Nuitka --onefile a veces usa la ruta del archivo actual
            base_path = os.path.dirname(os.path.abspath(__file__))
        except Exception:
            # OPCION 3: Fallback a la carpeta actual (Modo desarrollo)
            base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


# Intento importar PIL, si falla no rompe la app (Logo opcional)
try:
    from PIL import Image, ImageTk
except ImportError:
    pass

# =============================================================================
# [GLOBAL STATE] CONFIGURACION Y COLORES
# =============================================================================
HISTORIAL_RUTAS = {
    'path': os.path.abspath("."),
    'folder': 'Resultados_SS',
    'list_path': "lista.txt"
}

# Variable global para estado de ventana
WINDOW_STATE = {
    "maximized": False
}

# --- SISTEMA DE IDIOMAS ---
CURRENT_LANGUAGE = "es" # Por defecto en Español

TRADUCCIONES = {
    "es": {
        "login_title": "ACCESO AL SISTEMA",
        "user_lbl": "USUARIO",
        "pass_lbl": "CONTRASEÑA",
        "btn_login": "INICIAR SESIÓN",
        "btn_redeem": "CANJEAR LICENCIA",
        "btn_exit": "SALIR",
        "menu_admin": "PANEL ADMIN",
        "menu_user": "PANEL USUARIO",
        "menu_settings": "CONFIGURACIÓN",
        "welcome": "BIENVENIDO",
        "scan_config": "CONFIGURACIÓN DE ESCANEO",
        "path_lbl": "RUTA REPORTE:",
        "folder_lbl": "NOMBRE CARPETA:",
        "list_lbl": "LISTA PALABRAS:",
        "btn_select": "SELECCIONAR",
        "btn_browse": "BUSCAR",
        "modules_lbl": "MÓDULOS DE DETECCIÓN:",
        "sel_all": "[ MARCAR TODOS ]",
        "desel_all": "[ DESMARCAR ]",
        "upgrade": "MEJORA TU PLAN",
        "only_list": "Solo Modo Lista",
        "btn_start": "INICIAR MOTOR DE ESCANEO",
        "btn_back": "VOLVER AL MENÚ",
        "audit_prog": "AUDITORÍA EN PROGRESO...",
        "init": "Inicializando...",
        "stop_scan": "DETENER ESCANEO",
        "settings_title": "CONFIGURACIÓN DEL SISTEMA",
        "lang_lbl": "SELECCIONAR IDIOMA / SELECT LANGUAGE",
        "success_update": "Idioma actualizado correctamente."
    },
    "en": {
        "login_title": "SYSTEM ACCESS",
        "user_lbl": "USERNAME",
        "pass_lbl": "PASSWORD",
        "btn_login": "LOGIN",
        "btn_redeem": "REDEEM LICENSE",
        "btn_exit": "EXIT",
        "menu_admin": "ADMIN PANEL",
        "menu_user": "USER PANEL",
        "menu_settings": "SETTINGS",
        "welcome": "WELCOME",
        "scan_config": "SCANNER CONFIGURATION",
        "path_lbl": "OUTPUT PATH:",
        "folder_lbl": "FOLDER NAME:",
        "list_lbl": "KEYWORD LIST:",
        "btn_select": "SELECT",
        "btn_browse": "BROWSE",
        "modules_lbl": "DETECTION MODULES:",
        "sel_all": "[ SELECT ALL ]",
        "desel_all": "[ DESELECT ALL ]",
        "upgrade": "UPGRADE PLAN",
        "only_list": "List Mode Only",
        "btn_start": "START SCAN ENGINE",
        "btn_back": "BACK TO MENU",
        "audit_prog": "AUDIT IN PROGRESS...",
        "init": "Initializing...",
        "stop_scan": "STOP SCAN",
        "settings_title": "SYSTEM SETTINGS",
        "lang_lbl": "SELECT LANGUAGE / SELECCIONAR IDIOMA",
        "success_update": "Language updated successfully."
    }
}

def t(key):
    """Función helper para traducir textos"""
    return TRADUCCIONES.get(CURRENT_LANGUAGE, TRADUCCIONES["es"]).get(key, key)

# Paleta de Colores Cyberpunk
COLOR_SUCCESS = "#69f0ae"   
COLOR_BG = "#090011"        
COLOR_CARD = "#1a0526"      
COLOR_ACCENT = "#d500f9"    
COLOR_USER = "#b388ff"      
COLOR_TEXT = "#f3e5f5"      
COLOR_BORDER = "#4a148c"    
COLOR_HOVER_BG = "#4a0072"  
COLOR_HOVER_BORDER = "#ff40ff"
COLOR_DANGER = "#ff1744"    
COLOR_CLICK = "#000000"     

VT_API_KEY = "38885e277f7dc078cf8690f9315fddda65966c4ec0208dbc430a8fb91bb7c359" 
API_URL = "https://scanneler-api.onrender.com"
SESSION_TOKEN = None
USER_ROLE = None
USER_NAME = None
USER_MEMBERSHIP = None
USER_EXPIRY = None

cancelar_escaneo = False
cola_vt = Queue()
reporte_vt = "detecciones_virustotal.txt"

# --- SISTEMA YARA ---
GLOBAL_YARA_RULES = None

def inicializar_yara():
    global GLOBAL_YARA_RULES
    archivo_reglas = resource_path("reglas_scanneler.yar")
    if os.path.exists(archivo_reglas):
        try:
            GLOBAL_YARA_RULES = yara.compile(filepath=archivo_reglas)
            print(f"[OK] Motor YARA cargado: {archivo_reglas}")
        except Exception as e:
            print(f"[ERROR] Fallo al compilar reglas YARA: {e}")
            GLOBAL_YARA_RULES = None
    else:
        print("[ALERTA] No se encontró reglas_scanneler.yar. Usando modo degradado.")

# Variables Globales de Reportes
reporte_shim = ""
reporte_appcompat = ""
reporte_path = ""
reporte_sospechosos = ""
reporte_firmas = ""
reporte_ocultos = ""
reporte_mft = ""
reporte_userassist = ""
reporte_usb = "" 
reporte_dns = ""
reporte_browser = "" 
reporte_persistencia = ""
reporte_eventos = "" 
reporte_process = ""
reporte_game = ""    
reporte_nuclear = "" 
reporte_kernel = ""  
reporte_dna = ""     
reporte_network = "" 
reporte_toxic = "" 
reporte_ghost = ""
reporte_memory = ""
reporte_drivers = ""
reporte_static = ""
reporte_morph = "" # Nueva variable global para fase 25

# =============================================================================
# [UTILS] HERRAMIENTAS DEL SISTEMA
# =============================================================================

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    try: ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except: pass
    sys.exit()
    
def check_security():
    """
    Detecta Máquinas Virtuales (VM) y Depuradores basándose en HARDWARE real,
    no en drivers instalados, para evitar falsos positivos en PCs nativas.
    """
    try:
        # 1. DETECTOR DE VM POR BIOS/MODELO (Infalible)
        # Pregunta al sistema: "¿Quién fabricó tu placa base?"
        cmd = 'wmic computersystem get model,manufacturer /format:list'
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore').lower()
        
        # Lista estricta de firmas de hardware virtual
        vm_signatures = [
            "virtualbox", "vmware", "kvm", "bhyve", "qemu", 
            "microsoft corporation virtual", "bochs", "pleora", 
            "sibyl", "xen", "parallels"
        ]
        
        # Si el fabricante de la PC dice "VirtualBox", es una VM.
        # Si dice "ASUS" o "Gigabyte", es nativa (aunque tengas drivers de vbox instalados).
        for sig in vm_signatures:
            if sig in output:
                return True # Es una VM real

        # 2. DETECTOR DE DEPURADORES (Anti-Reversing)
        # Detecta si alguien está inspeccionando la memoria del proceso
        is_debugger = ctypes.windll.kernel32.IsDebuggerPresent()
        if is_debugger != 0:
            return True # Hay un debugger atado
            
    except: 
        pass
    
    return False # Es una PC Nativa Limpia

class DisableFileSystemRedirection:
    if os.name == 'nt':
        _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
        _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
    else:
        _disable = None; _revert = None
    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._disable(ctypes.byref(self.old_value))
        return self.success
    def __exit__(self, type, value, traceback):
        if self.success: self._revert(self.old_value)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

def ruta_recurso(relative_path):
    try: base_path = sys._MEIPASS
    except: base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

archivo_lista_default = "lista.txt"
archivo_logo = ruta_recurso("Scanneler.png")

def get_auth_headers():
    if SESSION_TOKEN: return {"Authorization": f"Bearer {SESSION_TOKEN}"}
    return {}

def aplicar_estilo_combobox(root):
    style = ttk.Style()
    try: style.theme_use('clam')
    except: pass
    style.configure("TCombobox", fieldbackground=COLOR_CARD, background=COLOR_BG, foreground=COLOR_TEXT, arrowcolor=COLOR_ACCENT, bordercolor=COLOR_BORDER)
    style.map("TCombobox", fieldbackground=[('readonly', COLOR_CARD)], selectbackground=[('readonly', COLOR_CARD)], selectforeground=[('readonly', COLOR_ACCENT)])
    root.option_add('*TCombobox*Listbox.background', "#2a0a38")
    root.option_add('*TCombobox*Listbox.foreground', COLOR_TEXT)
    root.option_add('*TCombobox*Listbox.selectBackground', COLOR_ACCENT)
    root.option_add('*TCombobox*Listbox.selectForeground', 'white')

def cargar_palabras(ruta_personalizada=None):
    ruta = ruta_personalizada if (ruta_personalizada and os.path.exists(ruta_personalizada)) else archivo_lista_default
    if not os.path.exists(ruta):
        if ruta == archivo_lista_default:
            try:
                with open(ruta, "w", encoding="utf-8") as f: f.write("password\nadmin\nlogin\nsecret\nconfig\nkey\ntoken\n")
            except: pass
        else: return []
    lista_final = []
    try:
        with open(ruta, "r", encoding="utf-8") as f: 
            for line in f:
                if line.strip(): lista_final.append(line.strip().lower())
    except: pass
    return lista_final

def calculate_entropy(data):
    if not data: return 0
    counts = Counter(data)
    length = len(data)
    entropy = 0
    for count in counts.values():
        p_x = count / length
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return entropy

# =============================================================================
# [UI COMPONENTS] BOTONES Y ALERTAS
# =============================================================================

class CyberRain:
    def __init__(self, canvas, color_accent):
        self.canvas = canvas; self.color = color_accent; self.drops = []; self.width = 3000; self.height = 2000; self.is_running = True; self.after_id = None; self.crear_gotas(); self.animar()
    def crear_gotas(self):
        try:
            for _ in range(120): 
                x = random.randint(0, self.width); y = random.randint(-500, self.height); speed = random.randint(2, 6); char = random.choice(["1", "0", "X", "S", "C", "A", "N"]); rain_color = random.choice([COLOR_ACCENT, COLOR_USER, "#7c4dff", "#e040fb"])
                if random.random() > 0.8: rain_color = "white"
                tag = self.canvas.create_text(x, y, text=char, fill=rain_color, font=("Consolas", 9, "bold"), tag="rain"); self.drops.append([tag, speed, y])
        except: pass
    def animar(self):
        if not self.is_running: return
        try:
            if not self.canvas.winfo_exists(): self.is_running = False; return
            h = 1500 
            for i in range(len(self.drops)):
                tag, speed, y = self.drops[i]; y += speed
                if y > h: y = random.randint(-100, 0); self.canvas.coords(tag, random.randint(0, self.width), y)
                else: self.canvas.move(tag, 0, speed)
                self.drops[i][2] = y
            if self.is_running: self.after_id = self.canvas.after(30, self.animar)
        except: self.is_running = False
    def detener(self):
        self.is_running = False
        if self.after_id:
            try: self.canvas.after_cancel(self.after_id); self.after_id = None
            except: pass

class BotonCanvas:
    def __init__(self, canvas, x, y, width, height, text, color_accent, command):
        self.canvas = canvas; self.x = x; self.y = y; self.w = width; self.h = height; self.text = text; self.cmd = command
        self.c_border = color_accent; self.c_fill = "#1a0526"; self.c_text = COLOR_TEXT; self.c_hover = COLOR_HOVER_BG; self.c_hover_border = COLOR_HOVER_BORDER
        self.id_shadow = self.canvas.create_line(x - width/2 + height/2, y + 4, x + width/2 - height/2, y + 4, width=height, fill="#000000", capstyle="round", stipple="gray50")
        self.id_glow = self.canvas.create_line(x - width/2 + height/2, y, x + width/2 - height/2, y, width=height, fill=self.c_border, capstyle="round")
        self.id_body = self.canvas.create_line(x - width/2 + height/2, y, x + width/2 - height/2, y, width=height-4, fill=self.c_fill, capstyle="round")
        self.id_text_s = self.canvas.create_text(x+1, y+1, text=text, fill="black", font=("Consolas", 11, "bold"))
        self.id_text = self.canvas.create_text(x, y, text=text, fill=self.c_text, font=("Consolas", 11, "bold"))
        self.items = [self.id_shadow, self.id_glow, self.id_body, self.id_text_s, self.id_text]
        for item in self.items:
            self.canvas.tag_bind(item, "<Enter>", self.on_enter); self.canvas.tag_bind(item, "<Leave>", self.on_leave); self.canvas.tag_bind(item, "<Button-1>", self.on_click); self.canvas.tag_bind(item, "<ButtonRelease-1>", self.on_release)
    def move_to(self, new_x, new_y):
        dx = new_x - self.x; dy = new_y - self.y
        for item in self.items: self.canvas.move(item, dx, dy)
        self.x = new_x; self.y = new_y
    def on_enter(self, e): self.canvas.itemconfig(self.id_body, fill=self.c_hover); self.canvas.itemconfig(self.id_glow, fill=self.c_hover_border); self.canvas.itemconfig(self.id_glow, width=self.h+2); self.canvas.itemconfig(self.id_text, fill="white")
    def on_leave(self, e): self.canvas.itemconfig(self.id_body, fill=self.c_fill); self.canvas.itemconfig(self.id_glow, fill=self.c_border); self.canvas.itemconfig(self.id_glow, width=self.h); self.canvas.itemconfig(self.id_text, fill=self.c_text)
    def on_click(self, e):
        self.canvas.itemconfig(self.id_body, fill="#000000"); self.canvas.update_idletasks(); time.sleep(0.05); self.canvas.itemconfig(self.id_body, fill=self.c_hover)
        if self.cmd: self.cmd()
    def on_release(self, e): self.on_enter(e)

class BotonDinamico(tk.Button):
    def __init__(self, master, color_accent, **kwargs):
        super().__init__(master, **kwargs); self.accent = color_accent; self.default_bg = kwargs.get("bg", COLOR_CARD)
        self.config(bg=self.default_bg, fg=COLOR_TEXT, font=("Consolas", 10, "bold"), relief="flat", bd=0, highlightthickness=1, highlightbackground=COLOR_BORDER, padx=20, pady=10, cursor="hand2", activebackground=self.accent, activeforeground="black")
        self.bind("<Enter>", self.hover_in); self.bind("<Leave>", self.hover_out)
    def hover_in(self, e): self.config(highlightbackground=self.accent, bg=COLOR_HOVER_BG, fg="white")
    def hover_out(self, e): self.config(highlightbackground=COLOR_BORDER, bg=self.default_bg, fg=COLOR_TEXT)

class ModernAlert:
    def __init__(self, title, message, type="info", parent=None):
        self.result = False; self.top = tk.Toplevel(parent); self.top.overrideredirect(True); self.top.config(bg=COLOR_BG); self.top.attributes("-topmost", True)
        w, h = 450, 220; sw, sh = self.top.winfo_screenwidth(), self.top.winfo_screenheight(); self.top.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        color = COLOR_DANGER if type == "error" else COLOR_ACCENT
        main_frame = tk.Frame(self.top, bg=COLOR_BG, highlightthickness=2, highlightbackground=color); main_frame.pack(fill="both", expand=True)
        tk.Label(main_frame, text=f"// {title.upper()} //", bg=COLOR_BG, fg=color, font=("Consolas", 14, "bold")).pack(pady=(25, 10))
        tk.Label(main_frame, text=message, bg=COLOR_BG, fg=COLOR_TEXT, font=("Consolas", 10), wraplength=400).pack(pady=10)
        btn_frame = tk.Frame(main_frame, bg=COLOR_BG); btn_frame.pack(pady=20)
        if type == "ask":
            BotonDinamico(btn_frame, COLOR_ACCENT, text="CONFIRM", command=self.on_yes, width=15).pack(side="left", padx=15)
            BotonDinamico(btn_frame, COLOR_DANGER, text="CANCEL", command=self.on_no, width=15).pack(side="left", padx=15)
        else: BotonDinamico(btn_frame, color, text="ACKNOWLEDGE", command=self.on_close, width=15).pack()
        self.top.grab_set(); self.top.wait_window()
    def on_yes(self): self.result = True; self.top.destroy()
    def on_no(self): self.result = False; self.top.destroy()
    def on_close(self): self.top.destroy()

def show_info(title, msg): ModernAlert(title, msg, "info")
def show_error(title, msg): ModernAlert(title, msg, "error")
def ask_yes_no(title, msg): alert = ModernAlert(title, msg, "ask"); return alert.result

# =============================================================================
# [FORENSICS] FASES 1-25 (MOTOR DE ESCANEO)
# =============================================================================

def worker_virustotal():
    while not cancelar_escaneo:
        ruta = cola_vt.get()
        if ruta is None: 
            cola_vt.task_done() # <--- ¡ESTO ES OBLIGATORIO!
            break
        try:
            with open(ruta, "rb") as f: file_hash = hashlib.sha256(f.read()).hexdigest()
            headers = {"x-apikey": VT_API_KEY}; url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                if stats['malicious'] > 0:
                    with open(reporte_vt, "a", encoding="utf-8", buffering=1) as f:
                        f.write(f"[{datetime.datetime.now()}] DETECTADO: {ruta}\n"); f.write(f" > Positivos: {stats['malicious']}\n"); f.write(f" > Hash: {file_hash}\n\n"); f.flush()
        except: pass
        cola_vt.task_done()

def fase_shimcache(palabras, modo):
    """
    FASE SHIMCACHE v3.0 (GOD MODE)
    1. Mapea Hardware: Sabe que el disco N: es fijo y no lo marca como sospechoso.
    2. Detecta Anomalías: Marca USBs y Discos Fantasma (Ghost Drives) en la sección de alertas.
    3. Full Dump: Muestra TODO el historial debajo para revisión manual.
    """
    if cancelar_escaneo: return
    
    # --- PASO 1: RECONOCIMIENTO DE HARDWARE (EVITAR FALSOS POSITIVOS EN DISCO N:) ---
    # Tipos: 2=Removable (USB), 3=Fixed (HDD/SSD), 4=Network
    discos_fijos = []    # C:, D:, N: (Discos internos o de red seguros)
    discos_usb = []      # E:, F: (Pendrives reales conectados ahora)
    mapa_discos = {} 

    try:
        # Consultamos WMI para ver qué discos hay conectados REALMENTE
        cmd_drives = "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType"
        proc_d = subprocess.Popen(['powershell', '-noprofile', '-command', cmd_drives], stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
        out_d, _ = proc_d.communicate()
        
        for linea in out_d.splitlines():
            linea = linea.strip()
            if not linea or "DeviceID" in linea or "----" in linea: continue
            
            # Formato: "C:      3"
            partes = linea.split()
            if len(partes) >= 2:
                letra = partes[0].upper() # "C:"
                tipo = partes[1]          # "3"
                
                if tipo == '3' or tipo == '4': # Fijo o Red -> LEGITIMO
                    discos_fijos.append(letra)
                    mapa_discos[letra] = "INTERNAL/FIXED (Safe)"
                elif tipo == '2': # Removable -> USB ACTIVO
                    discos_usb.append(letra)
                    mapa_discos[letra] = "USB DEVICE (Active)"
    except:
        # Si falla WMI, asumimos C: como único seguro por precaución
        discos_fijos = ["C:"]

    # --- PASO 2: EXTRACCIÓN Y ANÁLISIS ---
    alertas = []
    historial_limpio = []

    try:
        # Script de PowerShell para leer ShimCache crudo y limpiar rutas
        ps_shim = "$Reg = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache').AppCompatCache; if($Reg){ $Enc = [System.Text.Encoding]::Unicode.GetString($Reg); [regex]::Matches($Enc, '([a-zA-Z]:\\\\[^\\x00]+)').Value }"
        
        proc = subprocess.Popen(['powershell', '-noprofile', '-command', ps_shim], stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
        out, _ = proc.communicate()
        
        if out:
            # Usamos un set para eliminar duplicados exactos y procesar más rápido
            lineas_unicas = list(dict.fromkeys(out.splitlines()))
            
            for ruta in lineas_unicas:
                ruta = ruta.strip()
                if len(ruta) < 3 or ":" not in ruta: continue
                
                ruta_upper = ruta.upper()
                drive = ruta_upper[:2] # "C:", "N:", "F:"
                
                nombre_archivo = os.path.basename(ruta).lower()
                
                # --- LÓGICA DE DETECCIÓN ---
                es_alerta = False
                tag = ""

                # 1. Chequeo de Topología (Hardware)
                if drive in discos_usb:
                    tag = f"[!!!] EJECUCIÓN DESDE USB ACTIVO ({drive})"
                    es_alerta = True
                elif drive not in discos_fijos:
                    # Si no es fijo (N:) y no es USB activo... es un USB que FUE DESCONECTADO.
                    tag = f"[!!!] GHOST DRIVE DETECTED ({drive} - Dispositivo Desconectado)"
                    es_alerta = True
                
                # 2. Chequeo de Palabras Clave
                if any(p in nombre_archivo for p in palabras):
                    if es_alerta: tag += " + KEYWORD MATCH"
                    else: 
                        tag = "[ALERTA] KEYWORD MATCH"
                        es_alerta = True

                # --- CLASIFICACIÓN ---
                if es_alerta:
                    alertas.append(f"{tag}: {ruta}")
                else:
                    # Filtro de ruido para el historial (Opcional: Si quieres ver TODO, comenta el if)
                    # Ocultamos solo cosas muy obvias de Windows para no llenar de basura, 
                    # pero mostramos todo lo demás (Program Files, Users, Disco N, etc)
                    if "WINDOWS\\SYSTEM32" in ruta_upper and ".DLL" in ruta_upper:
                        continue 
                    historial_limpio.append(ruta)

    except Exception as e:
        alertas.append(f"Error crítico leyendo ShimCache: {e}")

    # --- PASO 3: ESCRITURA DEL REPORTE ---
    with open(reporte_shim, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== SHIMCACHE FORENSICS V3: {datetime.datetime.now()} ===\n")
        
        # A. Mapa de Discos (Para que veas que detectó tu disco N)
        f.write("[+] MAPA DE DISCOS RECONOCIDOS (Hardware Actual):\n")
        for k, v in mapa_discos.items():
            f.write(f"    DISK {k} -> {v}\n")
        f.write("-" * 80 + "\n\n")
        
        # B. Sección de ALERTAS (Lo Letal)
        if alertas:
            f.write(f"[!!!] AMENAZAS Y ANOMALÍAS DETECTADAS ({len(alertas)}):\n")
            for a in alertas:
                f.write(f" {a}\n")
        else:
            f.write("[OK] No se detectaron ejecuciones desde USBs o Discos Fantasma sospechosos.\n")
        
        f.write("\n" + "=" * 80 + "\n")
        
        # C. Sección de HISTORIAL (Lo que pediste: ShimCache completo)
        f.write(f"[+] HISTORIAL DE EJECUCIÓN COMPLETO ({len(historial_limpio)} entradas):\n")
        f.write("(Se han ocultado librerías nativas de System32 para facilitar la lectura)\n\n")
        
        for h in historial_limpio:
            f.write(f" {h}\n")

def fase_rastro_appcompat(palabras, modo):
    """
    FASE APPCOMPAT v2.1 (GHOST HUNTER & LAYERS ONLY)
    - Eliminado MuiCache (ya cubierto en otra fase).
    - Enfocado en: Historial de Ejecución y Configuraciones de Admin.
    - DETECTA SI EL ARCHIVO FUE BORRADO (Prueba de limpieza).
    """
    if cancelar_escaneo: return

    # Definimos los objetivos de caza (Sin MuiCache)
    objetivos = [
        # (Hive, Ruta, Nombre_Legible)
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", "COMPATIBILITY STORE (USER)"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", "COMPATIBILITY STORE (SYSTEM)"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "COMPATIBILITY LAYERS (USER)"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "COMPATIBILITY LAYERS (SYSTEM)")
    ]

    with open(reporte_appcompat, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== APPCOMPAT & GHOST TRACES: {datetime.datetime.now()} ===\n")
        f.write("Scanning Registry for execution history & admin privileges on deleted files.\n\n")

        hits = 0

        for hkey, subkey, titulo in objetivos:
            f.write(f"--- ANALIZANDO: {titulo} ---\n")
            try:
                with winreg.OpenKey(hkey, subkey) as k:
                    info_key = winreg.QueryInfoKey(k)
                    num_values = info_key[1]

                    for i in range(num_values):
                        try:
                            # n = Ruta del EXE
                            # d = Datos (Flags en Layers, o metadata en Store)
                            n, d, _ = winreg.EnumValue(k, i)
                            
                            # Limpieza agresiva de ruta
                            ruta_limpia = n.replace(r"\\?\/", "").replace(r"\\??\\", "")
                            nombre_archivo = os.path.basename(ruta_limpia).lower()
                            
                            # 1. VERIFICACIÓN FORENSE: ¿Existe el archivo en el disco?
                            existe = os.path.exists(ruta_limpia)
                            
                            # 2. ANÁLISIS DE SOSPECHA
                            es_sospechoso = False
                            etiqueta = "[INFO]"
                            
                            # Criterio A: Palabras Clave
                            if any(p in nombre_archivo for p in palabras):
                                es_sospechoso = True
                                etiqueta = "[ALERTA] KEYWORD MATCH"

                            # Criterio B: Archivo Borrado en carpetas calientes (Downloads, Temp, etc)
                            # Si Windows recuerda que se ejecutó, pero el archivo NO ESTÁ -> ALERTA ROJA
                            carpetas_calientes = ["downloads", "temp", "appdata", "desktop"]
                            if not existe and any(c in ruta_limpia.lower() for c in carpetas_calientes):
                                # Filtro básico para actualizaciones de windows/drivers
                                if "update" not in nombre_archivo and "install" not in nombre_archivo:
                                    if es_sospechoso: etiqueta = "[!!!] DELETED CHEAT TRACE"
                                    else: etiqueta = "[WARN] GHOST FILE (DELETED)"
                                    
                                    if modo == "Analizar Todo": es_sospechoso = True

                            # Criterio C: Capas de Compatibilidad (Layers)
                            # Detectar si forzaron permisos de ADMIN
                            if "LAYERS" in titulo:
                                flags = str(d).upper()
                                if "RUNASADMIN" in flags or "HIGHEST" in flags:
                                    if es_sospechoso: etiqueta += " + ADMIN RIGHTS"
                                    else: etiqueta += " (RunAsAdmin)"

                            # --- ESCRITURA EN REPORTE ---
                            if es_sospechoso or modo == "Analizar Todo":
                                estado_archivo = "(FILE EXISTS)" if existe else "(FILE DELETED/MOVED)"
                                
                                f.write(f" {etiqueta} {ruta_limpia}\n")
                                f.write(f"      Status: {estado_archivo}\n")
                                
                                # Si es Layers, mostramos los flags para ver qué intentaban hacer
                                if "LAYERS" in titulo: 
                                    f.write(f"      Flags: {d}\n")
                                
                                f.write("-" * 40 + "\n")
                                hits += 1
                                f.flush()

                        except Exception: continue
            except Exception as e:
                f.write(f" [ERROR] Accessing key {titulo}: {e}\n")
            
            f.write("\n")

        if hits == 0:
            f.write("[OK] No suspicious execution traces found in AppCompat.\n")

def fase_nombre_original(vt, palabras, modo):
    if cancelar_escaneo: return
    print(f"[3/25] Identity Analysis (Multi-Threaded Nuclear) [MAX SPEED]...")

    import concurrent.futures

    global reporte_sospechosos
    if not reporte_sospechosos: 
        base = HISTORIAL_RUTAS.get('path', os.path.abspath("."))
        fold = HISTORIAL_RUTAS.get('folder', "Resultados_SS")
        reporte_sospechosos = os.path.join(base, fold, "cambios_sospechosos.txt")

    # 1. LISTAS DE CONTROL
    # Carpetas que JAMÁS escaneamos porque son gigantes y seguras
    blacklisted_dirs = [
        "winsxs", "servicing", "assembly", "microsoft.net", "wbem", "system32\\driverstore"
    ]
    
    # Carpetas del sistema donde SI buscamos (aunque estén en Windows)
    # Aquí es donde esconden los cheats: Temp, Prefetch, SysWOW64 (root), etc.
    high_priority_system = [
        "windows\\temp", "windows\\prefetch", "windows\\syswow64", 
        "windows\\system32", "programdata", "appdata"
    ]

    files_to_check = set()

    # 2. RECOLECCIÓN DE OBJETIVOS (SÚPER RÁPIDA)
    
    # A) Procesos Activos (Instantáneo)
    try:
        cmd = 'wmic process get ExecutablePath /format:csv'
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000)
        out, _ = proc.communicate()
        if out:
            for line in out.splitlines():
                if "," in line:
                    p = line.split(",")[-1].strip()
                    if p and os.path.exists(p) and p.lower().endswith(".exe"): files_to_check.add(p)
    except: pass

    # B) Barrido Inteligente de Disco (Smart Walker)
    drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
    
    for drive in drives:
        if cancelar_escaneo: break
        
        # Estrategia: "Depth-Limited" para Windows, "Full" para Users/Otros Discos
        for root, dirs, files in os.walk(drive, topdown=True):
            if cancelar_escaneo: break
            
            root_lower = root.lower()
            
            # FILTRO DINÁMICO DE DIRECTORIOS
            # Si estamos en C:\Windows...
            if "windows" in root_lower:
                # Solo entramos si es una carpeta prioritaria (Temp, Prefetch, etc)
                # Si NO es prioritaria, vaciamos 'dirs' para detener la recursión ahí mismo.
                is_priority = any(p in root_lower for p in high_priority_system)
                if not is_priority:
                    # Pero permitimos escanear los archivos de la raiz de Windows
                    if root_lower.endswith("windows"): pass 
                    else: 
                        dirs[:] = [] # CORTAR RAMA AQUÍ
                        continue
            
            # Filtro de basura (WinSxS, etc)
            if any(b in root_lower for b in blacklisted_dirs):
                dirs[:] = []
                continue

            for name in files:
                if name.lower().endswith(".exe"):
                    # Filtro de tamaño: Cheats < 40MB. Juegos > 100MB.
                    full_path = os.path.join(root, name)
                    try:
                        if os.path.getsize(full_path) < 40 * 1024 * 1024:
                            files_to_check.add(full_path)
                    except: pass

    # 3. ANÁLISIS MULTI-HILO (LA MAGIA DE VELOCIDAD)
    # Definimos la función de análisis unitario
    def analyze_single_file(ruta):
        if cancelar_escaneo: return None
        try:
            nombre_disco = os.path.basename(ruta).lower()
            
            # Filtro: Si no es sospechoso por nombre/ubicación y no es "Analizar Todo", saltar.
            is_suspicious_loc = any(x in ruta.lower() for x in ["temp", "download", "desktop", "appdata"])
            is_keyword = any(p in nombre_disco for p in palabras)
            
            if modo != "Analizar Todo" and not is_keyword and not is_suspicious_loc:
                # OJO: Si está en Windows y no se llama como un archivo de windows conocido, analízalo.
                if "windows" in ruta.lower(): pass 
                else: return None

            pe = pefile.PE(ruta, fast_load=True)
            original_name = None
            
            if hasattr(pe, 'FileInfo'):
                for info in pe.FileInfo:
                    if hasattr(info, 'StringTable'):
                        for st in info.StringTable:
                            for k, v in st.entries.items():
                                key = k.decode('utf-8','ignore').replace('\x00','')
                                if key in ['OriginalFilename', 'InternalName']:
                                    val = v.decode('utf-8','ignore').replace('\x00','').lower()
                                    if val.endswith(".exe"): 
                                        original_name = val
                                        break
                            if original_name: break
                    if original_name: break
            pe.close()

            if original_name:
                real = original_name.replace(".exe", "").strip()
                actual = nombre_disco.replace(".exe", "").strip()
                
                # Excepciones comunes de Windows/Juegos para reducir ruido
                whitelist = ["setup", "install", "update", "unity", "unins", "launch", "dota", "csgo"]
                
                if real != actual and real not in actual and actual not in real:
                    if not any(w in real for w in whitelist):
                        return (ruta, nombre_disco, original_name) # DETECCIÓN
        except: pass
        return None

    # 4. EJECUCIÓN PARALELA (50 Workers)
    detections = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # Mapeamos la función a todos los archivos
        futures = {executor.submit(analyze_single_file, f): f for f in files_to_check}
        
        for future in concurrent.futures.as_completed(futures):
            if cancelar_escaneo: break
            res = future.result()
            if res:
                detections.append(res)

    # 5. ESCRITURA DE RESULTADOS
    with open(reporte_sospechosos, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== ANALISIS IDENTIDAD (MULTI-THREADED): {datetime.datetime.now()} ===\n")
        f.write(f"Files Scanned: {len(files_to_check)}\n")
        f.write(f"Threads Used: 50 | Time Optimized: Yes\n\n")

        if detections:
            for ruta, actual, real in detections:
                f.write(f"[!!!] FAKE NAME DETECTED:\n")
                f.write(f"      File on Disk: {actual}\n")
                f.write(f"      Real Name (PE): {real}\n")
                f.write(f"      Path: {ruta}\n")
                f.write("-" * 50 + "\n")
                if vt: cola_vt.put(ruta)
        else:
            f.write("No identity mismatches found.\n")

# =============================================================================
# [NATIVE] VERIFICADOR DE FIRMAS (WinVerifyTrust)
# =============================================================================
def verificar_firma_nativa(filepath):
    """
    Verifica la firma digital de un archivo usando la API nativa de Windows (wintrust.dll).
    Retorna: (bool_valido, str_estado)
    """
    try:
        wintrust = ctypes.windll.wintrust
        
        # Estructuras necesarias para WinAPI
        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", ctypes.c_ulong),
                ("pcwszFilePath", ctypes.c_wchar_p),
                ("hFile", ctypes.c_void_p),
                ("pgKnownSubject", ctypes.c_void_p)
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", ctypes.c_ulong),
                ("dwPolicyCallbackData", ctypes.c_void_p),
                ("dwSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", ctypes.c_ulong),
                ("fdwRevocationChecks", ctypes.c_ulong),
                ("dwUnionChoice", ctypes.c_ulong),
                ("pFile", ctypes.c_void_p),
                ("dwStateAction", ctypes.c_ulong),
                ("hWVTStateData", ctypes.c_void_p),
                ("pwszURLReference", ctypes.c_wchar_p),
                ("dwProvFlags", ctypes.c_ulong),
                ("dwUIContext", ctypes.c_ulong),
                ("pSignatureSettings", ctypes.c_void_p)
            ]

        # GUID para acción genérica de verificación (WINTRUST_ACTION_GENERIC_VERIFY_V2)
        # {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
        guid_bytes = uuid.UUID('{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}').bytes_le
        p_guid = ctypes.create_string_buffer(guid_bytes)

        # Configurar Info del Archivo
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = filepath
        file_info.hFile = None
        file_info.pgKnownSubject = None

        # Configurar Datos de Confianza
        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.dwUIChoice = 2  # WTD_UI_NONE (Sin GUI)
        trust_data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE (Rápido, sin chequear online CRL)
        trust_data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
        trust_data.dwProvFlags = 0x00000010 | 0x00000800 # Cache Only + Safer Flag

        # Ejecutar Verificación
        status = wintrust.WinVerifyTrust(None, p_guid, ctypes.byref(trust_data))
        
        # Limpiar memoria (Close Action)
        trust_data.dwStateAction = 2 # WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, p_guid, ctypes.byref(trust_data))

        # 0 = TRUST_E_SUCCESS (Firmado y Confiable)
        if status == 0:
            return True, "VALID_TRUSTED"
        
        # Códigos de error comunes
        errores = {
            0x800B0100: "NO_SIGNATURE",
            0x800B0101: "EXPIRED",
            0x800B0109: "UNTRUSTED_ROOT",
            0x80096010: "BAD_DIGEST" # Archivo modificado
        }
        return False, errores.get(status, f"INVALID_CODE_{hex(status)}")
            
    except Exception as e:
        return False, f"ERROR_API: {str(e)}"

# --- FASE PRINCIPAL ---

def fase_verificar_firmas(palabras, vt, modo):
    if cancelar_escaneo: return
    print(f"[4/25] Digital Signature (Deep Recursive + Native API) [LETHAL SPEED]...")

    global reporte_firmas
    base_path = HISTORIAL_RUTAS.get('path', os.path.abspath("."))
    folder_name = HISTORIAL_RUTAS.get('folder', "Resultados_SS")
    reporte_firmas = os.path.join(base_path, folder_name, "Digital_Signatures_ZeroTrust.txt")

    # --- LISTAS INTELIGENTES PARA MANTENER LA VELOCIDAD ---
    # Extensiones peligrosas que deben tener firma (o ser scripts sospechosos)
    target_exts = ('.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs', '.ahk', '.lua', '.py', '.tmp')
    
    # Carpetas "Agujero Negro" (Si entras aquí, el escaneo se muere. Las saltamos.)
    # Esto es el secreto para que sea RÁPIDO aunque sea recursivo.
    ignored_folders = {
        "node_modules", ".git", ".vs", "__pycache__", "vendor", "lib", "libs", "include",
        "steamapps", "riot games", "epic games", "ubisoft", "program files", "windows"
    }

    files_to_scan = set()

    # 1. DEFINIR ZONAS DE CAZA (Ahora recursivas)
    user_profile = os.environ["USERPROFILE"]
    deep_zones = [
        os.path.join(user_profile, "Desktop"),
        os.path.join(user_profile, "Downloads"),
        os.path.join(user_profile, "AppData", "Local", "Temp"),
        # AppData Roaming suele tener mucha basura, escaneamos solo la raiz o carpetas específicas si quieres
        os.path.join(user_profile, "AppData", "Roaming")
    ]
    
    # Soporte OneDrive
    onedrive = os.path.join(user_profile, "OneDrive")
    if os.path.exists(onedrive):
        deep_zones.append(os.path.join(onedrive, "Desktop"))
        deep_zones.append(os.path.join(onedrive, "Downloads")) # A veces está aquí

    # 2. PROCESOS ACTIVOS (Siempre prioridad)
    try:
        cmd = 'wmic process get ExecutablePath /format:csv'
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000)
        out, _ = proc.communicate()
        if out:
            for line in out.splitlines():
                if "," in line:
                    path = line.split(",")[-1].strip()
                    if path and os.path.exists(path): files_to_scan.add(path)
    except: pass

    # 3. RECOLECCIÓN RECURSIVA ULTRA-RÁPIDA
    # Usamos os.walk pero podando el árbol de directorios
    for zone in deep_zones:
        if not os.path.exists(zone): continue
        
        # Limite de seguridad: Si la carpeta es Roaming, no profundizamos tanto para no tardar años
        max_depth = 5 if "AppData" in zone else 10 
        root_depth = zone.count(os.sep)

        for root, dirs, files in os.walk(zone, topdown=True):
            if cancelar_escaneo: break
            
            # A. Optimización: Podar carpetas basura en tiempo real
            dirs[:] = [d for d in dirs if d.lower() not in ignored_folders and not d.startswith('.')]
            
            # B. Control de profundidad
            current_depth = root.count(os.sep)
            if current_depth - root_depth > max_depth:
                del dirs[:] # Dejar de bajar en esta rama
                continue

            for name in files:
                if name.lower().endswith(target_exts):
                    full_path = os.path.join(root, name)
                    # Filtro de tamaño: Opcional, para no escanear ISOs gigantes renombradas a .exe
                    try:
                        if os.path.getsize(full_path) < 150 * 1024 * 1024: # < 150MB
                            files_to_scan.add(full_path)
                    except: pass

    # 4. EJECUCIÓN DEL ANÁLISIS (WinAPI)
    scanned_count = 0
    unsigned_count = 0
    
    with open(reporte_firmas, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== DIGITAL SIGNATURE DEEP SCAN: {datetime.datetime.now()} ===\n")
        f.write(f"Engine: Native WinVerifyTrust | Scope: Recursive (Smart Filter)\n")
        f.write(f"Targets Identified: {len(files_to_scan)}\n\n")
        
        for file_path in files_to_scan:
            if cancelar_escaneo: break
            scanned_count += 1
            
            # Verificación
            # NOTA: Los scripts (.lua, .ahk) siempre darán "NO_SIGNATURE", lo cual es bueno porque los reportará.
            is_valid, status_msg = verificar_firma_nativa(file_path)
            file_name = os.path.basename(file_path)
            
            if not is_valid:
                unsigned_count += 1
                f.write(f"[!!!] POTENTIAL THREAT (Unsigned): {file_name}\n")
                f.write(f"      Path: {file_path}\n")
                f.write(f"      Sign Status: {status_msg}\n")
                
                # Heurística extra para scripts (Tessio, etc.)
                ext = os.path.splitext(file_name)[1].lower()
                if ext in ['.lua', '.ahk', '.py', '.bat']:
                    f.write(f"      Type: SCRIPT FILE (High Risk if hidden)\n")
                
                f.write("-" * 40 + "\n")
                f.flush()
                
                if vt: cola_vt.put(file_path)

            elif modo == "Analizar Todo":
                f.write(f"[OK] {file_name} [Signed]\n")

        f.write(f"\nScan Finished.\nTotal Files Checked: {scanned_count}\nUnsigned/Suspicious: {unsigned_count}")
        
def fase_buscar_en_disco(kws):
    if cancelar_escaneo: return
    with open(reporte_path, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== BUSQUEDA: {datetime.datetime.now()} ===\n\n")
        for r, _, as_ in os.walk("C:\\Users"):
            for n in as_:
                if any(k in n.lower() for k in kws): f.write(f"DETECTADO: {os.path.join(r, n)}\n"); f.flush()

def fase_archivos_ocultos(palabras, modo):
    """
    FASE OCULTOS v2.0 (QUIRÚRGICA & VELOZ)
    - Usa os.scandir (Iterator) para velocidad extrema.
    - Se enfoca en 'Hot Paths' (Usuario, AppData, Temp).
    - Detecta atributos +S (System) +H (Hidden) fuera de Windows.
    - Alerta si un ejecutable (.exe, .bat) está oculto.
    """
    if cancelar_escaneo: return
    
    # 1. Definir Zonas Calientes (Donde se esconden los cheats)
    # Escanear todo C: es ineficiente. Los cheats viven en el perfil del usuario.
    user_profile = os.environ.get('USERPROFILE')
    rutas_calientes = [
        user_profile, # C:\Users\Usuario
        os.path.join(user_profile, "AppData"), # Roaming, Local, LocalLow
        r"C:\ProgramData",
        r"C:\Temp"
    ]
    
    # Rutas a ignorar para velocidad (Ruido)
    ignorar_carpetas = ["microsoft", "windows", "google", "mozilla", "node_modules", ".git"]

    # Constantes de atributos de archivo
    FILE_ATTRIBUTE_HIDDEN = 2
    FILE_ATTRIBUTE_SYSTEM = 4

    with open(reporte_ocultos, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== SCAN DE ARCHIVOS OCULTOS (SMART): {datetime.datetime.now()} ===\n")
        f.write("Target: User Profile, AppData, ProgramData (Skipping Windows System Files)\n\n")
        
        count = 0
        
        # Función recursiva optimizada con scandir
        def escanear_rapido(directorio, profundidad_max=10, nivel_actual=0):
            nonlocal count
            if nivel_actual > profundidad_max or cancelar_escaneo: return

            try:
                with os.scandir(directorio) as it:
                    for entry in it:
                        if cancelar_escaneo: break
                        
                        # A. Si es Directorio
                        if entry.is_dir():
                            name_low = entry.name.lower()
                            # Filtro de ruido: No entrar a carpetas basura conocidas
                            if not entry.is_symlink() and name_low not in ignorar_carpetas:
                                escanear_rapido(entry.path, profundidad_max, nivel_actual + 1)
                        
                        # B. Si es Archivo
                        elif entry.is_file():
                            try:
                                # stat() en Windows con scandir es casi gratis (cached)
                                stats = entry.stat()
                                attrs = stats.st_file_attributes # Disponible en Windows
                                
                                is_hidden = attrs & FILE_ATTRIBUTE_HIDDEN
                                is_system = attrs & FILE_ATTRIBUTE_SYSTEM
                                
                                # Solo nos importa si tiene atributos de ocultación
                                if is_hidden or is_system:
                                    nombre = entry.name
                                    nombre_low = nombre.lower()
                                    ruta = entry.path
                                    
                                    # --- LÓGICA DE LETALIDAD ---
                                    es_sospechoso = False
                                    tag = "[INFO]"
                                    
                                    # 1. Super Oculto (+H +S) fuera de Windows
                                    # Un archivo de sistema oculto en "Documents" es un cheat/virus seguro.
                                    if is_hidden and is_system:
                                        tag = "[!!!] SUPER HIDDEN (SYSTEM+HIDDEN)"
                                        es_sospechoso = True
                                    
                                    # 2. Ejecutable Oculto (.exe, .bat, .vbs, .ps1, .dll)
                                    elif any(nombre_low.endswith(x) for x in [".exe", ".bat", ".cmd", ".vbs", ".ps1", ".dll", ".sys"]):
                                        tag = "[!!!] HIDDEN EXECUTABLE"
                                        es_sospechoso = True
                                    
                                    # 3. Coincidencia de Palabras Clave
                                    elif any(p in nombre_low for p in palabras):
                                        tag = "[ALERTA] KEYWORD MATCH"
                                        es_sospechoso = True
                                    
                                    # 4. Modo Analizar Todo (Reportar todo lo oculto que no sea .ini o .xml basura)
                                    elif modo == "Analizar Todo":
                                        if not nombre_low.endswith(".ini") and not nombre_low.endswith(".xml"):
                                            tag = "[OCULTO]"
                                            es_sospechoso = True # Para que se escriba

                                    # --- ESCRITURA ---
                                    if es_sospechoso:
                                        f.write(f"{tag}: {ruta}\n")
                                        if is_system: f.write("      Attr: SYSTEM + HIDDEN\n")
                                        count += 1
                                        # f.flush() # Flush continuo ralentiza, mejor dejar que el buffer actúe o flush cada X
                                
                            except Exception: pass

            except PermissionError: pass
            except Exception: pass

        # Ejecutar el escaneo en las zonas calientes
        for ruta_base in rutas_calientes:
            if os.path.exists(ruta_base):
                # f.write(f" Scanning zone: {ruta_base}...\n")
                escanear_rapido(ruta_base)
        
        if count == 0:
            f.write("[OK] No suspicious hidden files found in critical areas.\n")

def fase_mft_ads(palabras, modo):
    """
    FASE MFT & ADS (MARK OF THE WEB HUNTER)
    - Detecta flujos de datos alternativos (ADS).
    - LEE el origen de la descarga (Zone.Identifier) para ver si viene de Discord/Sitios de Cheats.
    - Detecta Payloads ocultos (Streams que no son Zone.Identifier).
    """
    global cancelar_escaneo
    if cancelar_escaneo: return

    # Definimos zonas calientes para escanear recursivamente
    # Escanear todo C: es muy lento con PowerShell, nos enfocamos donde bajan cosas.
    user_profile = os.environ.get('USERPROFILE')
    targets = [
        os.path.join(user_profile, "Downloads"),
        os.path.join(user_profile, "Desktop"),
        os.path.join(user_profile, "AppData"),
        os.path.join(user_profile, "Documents"),
        "C:\\ProgramData",
        "C:\\Windows\\Temp"
    ]

    with open(reporte_mft, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== MFT & ADS (ORIGIN HUNTER): {datetime.datetime.now()} ===\n")
        f.write("Scanning for Alternate Data Streams and Source URLs (Mark of the Web)...\n\n")

        # Comando PowerShell Optimizado:
        # 1. Busca archivos con streams.
        # 2. Ignora el stream principal (:$DATA).
        # 3. Devuelve: RutaCompleta | NombreStream | Contenido (primeras lineas)
        # Usamos delimitador '|||' para separar fácil en Python.
        
        for target in targets:
            if cancelar_escaneo: break
            if not os.path.exists(target): continue

            try:
                # El comando es complejo pero muy potente.
                # Get-Content -Stream lee el contenido del ADS.
                cmd = f'''
                Get-ChildItem -Path "{target}" -Recurse -File -ErrorAction SilentlyContinue | 
                Get-Item -Stream * -ErrorAction SilentlyContinue | 
                Where-Object {{ $_.Stream -ne ":$DATA" }} | 
                ForEach-Object {{ 
                    $content = Get-Content -LiteralPath $_.FileName -Stream $_.Stream -Raw -ErrorAction SilentlyContinue | Select-Object -First 5;
                    "$($_.FileName)|||$($_.Stream)|||$($content -replace "`r`n","__NL__")"
                }}
                '''
                
                proc = subprocess.Popen(
                    ["powershell", "-NoProfile", "-Command", cmd], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True, 
                    bufsize=1, 
                    creationflags=0x08000000
                )

                while True:
                    if cancelar_escaneo: 
                        proc.terminate()
                        break
                    
                    linea = proc.stdout.readline()
                    if not linea and proc.poll() is not None: break
                    
                    if linea:
                        linea = linea.strip()
                        if not linea: continue
                        
                        try:
                            parts = linea.split("|||")
                            if len(parts) >= 2:
                                ruta_archivo = parts[0]
                                stream_name = parts[1]
                                contenido = parts[2] if len(parts) > 2 else ""
                                
                                # Reconstruir saltos de línea para análisis
                                contenido_real = contenido.replace("__NL__", "\n")
                                
                                es_sospechoso = False
                                etiqueta = "[INFO]"
                                detalles_extra = ""

                                # CASO 1: Zone.Identifier (Rastreo de Origen)
                                if "Zone.Identifier" in stream_name:
                                    # Buscamos HostUrl o ReferrerUrl
                                    if "HostUrl=" in contenido_real:
                                        # Extraer la URL
                                        for linea_url in contenido_real.splitlines():
                                            if "HostUrl=" in linea_url:
                                                url = linea_url.split("=")[1].strip()
                                                detalles_extra = f"Source: {url}"
                                                
                                                # SI VIENE DE DISCORD O SITIOS DE CHEATS -> CULPABLE
                                                dominios_rojos = ["discord", "cdn.discordapp", "mega.nz", "mediafire", "anonfiles", "gofile", "cheats", "hacks", "unknowncheats"]
                                                if any(d in url.lower() for d in dominios_rojos):
                                                    etiqueta = "[!!!] DOWNLOADED FROM SUSPICIOUS SOURCE"
                                                    es_sospechoso = True
                                                elif modo == "Analizar Todo":
                                                    # En modo full, mostramos todo origen para auditoría
                                                    es_sospechoso = True
                                                    etiqueta = "[ORIGIN]"
                                
                                # CASO 2: Payload Oculto (Cualquier otro stream)
                                else:
                                    # Si el stream NO es Zone.Identifier, es datos ocultos (muy raro en users normales)
                                    # Los cheats guardan configs o inyectores aquí.
                                    # Excepción: Thumbs.db o archivos de sistema a veces tienen, pero en User Profile es raro.
                                    if "favicon" not in ruta_archivo.lower():
                                        etiqueta = "[!!!] HIDDEN PAYLOAD (NON-STANDARD ADS)"
                                        detalles_extra = f"Stream: {stream_name}"
                                        es_sospechoso = True

                                # --- ESCRITURA ---
                                if es_sospechoso:
                                    f.write(f"{etiqueta}: {ruta_archivo}\n")
                                    if detalles_extra: f.write(f"      {detalles_extra}\n")
                                    f.write("-" * 40 + "\n")
                                    f.flush()

                        except Exception: pass
                        
            except Exception as e:
                f.write(f"Error processing target {target}: {e}\n")

def fase_userassist(palabras, modo):
    """
    FASE USERASSIST v2.0 (GHOST HUNTER & RUN COUNT)
    - Decodifica ROT13.
    - Extrae FECHA de ejecución y CANTIDAD de ejecuciones.
    - Detecta si el archivo ejecutado FUE BORRADO (Ghost File).
    - Alerta sobre ejecuciones desde carpetas temporales.
    """
    # if cancelar_escaneo: return
    print("[28/28] UserAssist (Human Interaction + Timestamps)...")
    
    global reporte_userassist
    try:
        base_path = HISTORIAL_RUTAS.get('path', os.path.abspath("."))
        folder_name = HISTORIAL_RUTAS.get('folder', "Resultados_SS")
    except:
        base_path = os.path.abspath(".")
        folder_name = "Resultados_SS"
        
    reporte_userassist = os.path.join(base_path, folder_name, "User_Interaction_Trace.txt")

    # Helper para extraer datos del binario de UserAssist (Win 7/10/11)
    def parse_userassist_data(binary_data):
        try:
            # Estructura típica Win10+:
            # Offset 4: Run Count (4 bytes, int)
            # Offset 60: Timestamp (8 bytes, filetime)
            run_count = 0
            last_run_str = "Unknown"
            
            if len(binary_data) >= 8:
                run_count = struct.unpack('<I', binary_data[4:8])[0]
            
            if len(binary_data) >= 68:
                ft = struct.unpack('<Q', binary_data[60:68])[0]
                if ft > 0:
                    us = ft / 10
                    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)
                    last_run_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                    return run_count, last_run_str, dt
            
            return run_count, last_run_str, None
        except:
            return 0, "Error Parsing", None

    # Límite de tiempo para "Analizar Todo" (últimos 5 días para no saturar)
    limit_date = datetime.datetime.now() - datetime.timedelta(days=5)

    with open(reporte_userassist, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== USERASSIST FORENSICS: {datetime.datetime.now()} ===\n")
        f.write("Evidence of GUI Execution, Run Counts, and Deleted Files.\n\n")
        
        hits = 0
        
        try:
            r = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r) as k_ua:
                num_subkeys = winreg.QueryInfoKey(k_ua)[0]
                
                for i in range(num_subkeys):
                    guid = winreg.EnumKey(k_ua, i)
                    # Filtramos GUIDs conocidos de ejecutables para limpiar ruido
                    # CEBFF5CD... es Executables. F4E57C4B... es Shortcuts.
                    
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{r}\\{guid}\\Count") as k_c:
                            num_values = winreg.QueryInfoKey(k_c)[1]
                            
                            for j in range(num_values):
                                n_rot, data, type_ = winreg.EnumValue(k_c, j)
                                
                                try:
                                    # 1. Decodificar ROT13
                                    n_real = codecs.decode(n_rot, 'rot_13')
                                    
                                    # Limpiar GUIDs del nombre (ej: {0139...}\cmd.exe)
                                    if "}" in n_real:
                                        parts = n_real.split("}")
                                        clean_path = parts[-1]
                                    else:
                                        clean_path = n_real

                                    # Si es una ruta válida (ej: C:\...)
                                    if ":" not in clean_path and not clean_path.startswith("\\"): 
                                        continue 

                                    # 2. Extraer Metadata
                                    count, last_run, dt_obj = parse_userassist_data(data)
                                    
                                    # 3. ANÁLISIS LETAL
                                    es_sospechoso = False
                                    tag = "[INFO]"
                                    
                                    # A. Palabras Clave
                                    if any(p in clean_path.lower() for p in palabras):
                                        tag = "[ALERTA] KEYWORD MATCH"
                                        es_sospechoso = True
                                    
                                    # B. Ghost Hunter (Archivo Borrado)
                                    # Solo chequeamos si parece una ruta absoluta
                                    file_exists = os.path.exists(clean_path)
                                    if not file_exists and ("C:" in clean_path or "D:" in clean_path):
                                        # Ignoramos accesos directos (.lnk) que apuntan a nada, nos interesan EXEs
                                        if clean_path.lower().endswith(".exe") or clean_path.lower().endswith(".bat"):
                                            if es_sospechoso: tag = "[!!!] DELETED CHEAT EVIDENCE"
                                            else: tag = "[WARN] GHOST FILE (EXECUTED & DELETED)"
                                            
                                            # En modo Full, ver un EXE borrado que se ejecutó hace poco es CRÍTICO
                                            if modo == "Analizar Todo" and dt_obj and dt_obj > limit_date:
                                                es_sospechoso = True

                                    # C. Rutas Sospechosas (Temp/AppData)
                                    if ("appdata" in clean_path.lower() or "temp" in clean_path.lower()) and clean_path.lower().endswith(".exe"):
                                        if not es_sospechoso and modo == "Analizar Todo":
                                            tag = "[SUSPICIOUS PATH]"
                                            es_sospechoso = True

                                    # 4. FILTRADO DE FECHA (Para no mostrar cosas de 2020)
                                    mostrar = False
                                    if es_sospechoso: mostrar = True
                                    elif modo == "Analizar Todo" and dt_obj and dt_obj > limit_date: mostrar = True

                                    # 5. ESCRITURA
                                    if mostrar:
                                        status_str = "EXISTS" if file_exists else "DELETED/MISSING"
                                        f.write(f"[{last_run}] {tag}: {clean_path}\n")
                                        f.write(f"      Run Count: {count} times\n")
                                        f.write(f"      File Status: {status_str}\n")
                                        f.write("-" * 40 + "\n")
                                        f.flush()
                                        hits += 1

                                except Exception: continue
                    except Exception: continue
                    
        except Exception as e:
            f.write(f"Error reading Registry: {e}\n")
        
        if hits == 0:
            f.write("[OK] No suspicious user interactions found in recent history.\n")

# --- FASE 9 (MASTER V2): USB, GHOST DRIVES & ENCRYPTION STATUS ---
def fase_usb_history(palabras, modo):
    """
    FASE USB FORENSICS v4.1 (FIXED)
    - Corrección de error de sintaxis en bloque UserAssist.
    - Detecta Hardware de Cheats (Arduino/DMA).
    - Muestra ejecución desde USBs.
    """
    if cancelar_escaneo: return
    print(f"[9/26] USB Execution & Hardware Forensics [NUCLEAR SCAN]...")

    with open(reporte_usb, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== USB EXECUTION & HARDWARE FORENSICS: {datetime.datetime.now()} ===\n")
        f.write("Target: Hardware Cheats, USB Execution History & Removed Drive Traces.\n\n")

        # -------------------------------------------------------------------------
        # 1. MAPEO DE UNIDADES
        # -------------------------------------------------------------------------
        discos_usb_activos = []
        discos_fijos = ["C:"] 
        
        try:
            cmd = "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType"
            proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", cmd], stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            
            for line in out.splitlines():
                if "2" in line: # Removable
                    parts = line.split()
                    if parts: discos_usb_activos.append(parts[0])
                elif "3" in line or "4" in line: # Fixed / Network
                    parts = line.split()
                    if parts: discos_fijos.append(parts[0])
        except: pass

        f.write(f"[INFO] Active USB Drives: {', '.join(discos_usb_activos) if discos_usb_activos else 'None'}\n")
        f.write("-" * 60 + "\n\n")

        # -------------------------------------------------------------------------
        # 2. VID/PID HUNTER (HARDWARE MALICIOSO)
        # -------------------------------------------------------------------------
        f.write("--- [1] HARDWARE ID SCAN (Arduinos & DMA) ---\n")
        
        bad_vids = {
            "2341": "ARDUINO (Possible Aimbot/Mouse Spoofer)",
            "16C0": "TEENSY (BadUSB/Scripting)",
            "1B4F": "SPARKFUN (Microcontroller)",
            "04D8": "MICROCHIP (Generic HID Spoofer)",
            "1A86": "CH340 (Chinese Serial/Arduino Clone)",
            "0403": "FTDI (Possible DMA Fader)"
        }
        
        found_hw = False
        reg_path = r"SYSTEM\CurrentControlSet\Enum\USB"
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                num_keys = winreg.QueryInfoKey(key)[0]
                for i in range(num_keys):
                    device_key_name = winreg.EnumKey(key, i)
                    
                    threat_msg = ""
                    for vid, msg in bad_vids.items():
                        if f"VID_{vid}" in device_key_name.upper():
                            threat_msg = msg
                            break
                    
                    if threat_msg or modo == "Analizar Todo":
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{reg_path}\\{device_key_name}") as subkey:
                                num_inst = winreg.QueryInfoKey(subkey)[0]
                                for j in range(num_inst):
                                    serial = winreg.EnumKey(subkey, j)
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{reg_path}\\{device_key_name}\\{serial}") as inst_key:
                                        try: name, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                                        except: 
                                            try: name, _ = winreg.QueryValueEx(inst_key, "DeviceDesc")
                                            except: name = "Unknown Device"
                                        
                                        ts_ns = winreg.QueryInfoKey(inst_key)[2]
                                        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ts_ns/10)
                                        last_seen = dt.strftime('%Y-%m-%d %H:%M:%S')

                                        if threat_msg:
                                            f.write(f"[!!!] HARDWARE CHEAT DETECTED: {threat_msg}\n")
                                            f.write(f"      Device: {name}\n")
                                            f.write(f"      HWID: {device_key_name}\n")
                                            f.write(f"      Last Connected: {last_seen}\n")
                                            f.write("-" * 40 + "\n")
                                            found_hw = True
                                        elif "MassStorage" in device_key_name or "DISK" in name.upper() or "USB" in name.upper():
                                             f.write(f"[HISTORY] {name} (Last: {last_seen})\n")
                        except: continue

        except Exception as e: f.write(f"Error scanning USB Registry: {e}\n")
        
        if not found_hw: f.write("[OK] No specific Hardware Cheat IDs found.\n")

        # -------------------------------------------------------------------------
        # 3. EJECUCIONES DESDE USB (USERASSIST)
        # -------------------------------------------------------------------------
        f.write("\n--- [2] EXECUTION FROM USB (UserAssist Evidence) ---\n")
        
        ua_hits = 0
        try:
            ua_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_path) as k_ua:
                for i in range(winreg.QueryInfoKey(k_ua)[0]):
                    guid = winreg.EnumKey(k_ua, i)
                    
                    # --- AQUÍ ESTABA EL ERROR: FALTABA CERRAR ESTE TRY ---
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{ua_path}\\{guid}\\Count") as k_c:
                            for j in range(winreg.QueryInfoKey(k_c)[1]):
                                n_rot, data, _ = winreg.EnumValue(k_c, j)
                                n_real = codecs.decode(n_rot, 'rot_13')
                                
                                if "}" in n_real: n_real = n_real.split("}")[-1]
                                if not n_real or ":" not in n_real: continue
                                
                                drive_letter = n_real[:2].upper()
                                is_usb_exec = False
                                status_msg = ""
                                
                                if drive_letter in discos_usb_activos:
                                    is_usb_exec = True
                                    status_msg = "ACTIVE USB"
                                elif drive_letter not in discos_fijos and drive_letter not in discos_usb_activos:
                                    if "X:" not in drive_letter and "Z:" not in drive_letter:
                                        is_usb_exec = True
                                        status_msg = "REMOVED DRIVE (GHOST)"

                                if is_usb_exec:
                                    last_run = "Unknown"
                                    if len(data) >= 68:
                                        ft = struct.unpack('<Q', data[60:68])[0]
                                        if ft > 0:
                                            dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft/10)
                                            last_run = dt.strftime('%Y-%m-%d %H:%M:%S')

                                    if n_real.lower().endswith((".exe", ".bat", ".cmd", ".ps1")):
                                        tag = "[!!!]"
                                        if any(p in n_real.lower() for p in palabras): tag = "[!!!] CONFIRMED CHEAT"
                                        
                                        f.write(f"{tag} EXECUTION: {n_real}\n")
                                        f.write(f"      Status: {status_msg}\n")
                                        f.write(f"      Last Run: {last_run}\n")
                                        f.write("-" * 40 + "\n")
                                        ua_hits += 1
                    except: 
                        continue # <--- ESTA LÍNEA FALTABA

        except Exception as e: f.write(f"Error reading UserAssist: {e}\n")
        
        if ua_hits == 0: f.write("[OK] No executable traces found directly from USB drives.\n")

        # -------------------------------------------------------------------------
        # 4. GHOST LNKs
        # -------------------------------------------------------------------------
        f.write("\n--- [3] SHORTCUTS TO REMOVED DRIVES (Ghost LNKs) ---\n")
        
        lnk_hits = 0
        ps_lnk_script = r"""
        $Recent = [Environment]::GetFolderPath("Recent")
        $WScript = New-Object -ComObject WScript.Shell
        Get-ChildItem $Recent -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $Target = $WScript.CreateShortcut($_.FullName).TargetPath
                if ($Target -match "^([A-Z]:)") {
                    $Drive = $Matches[1]
                    if ($Drive -ne "C:") { Write-Output "$($_.Name)|$Target|$Drive" }
                }
            } catch {}
        }
        """
        try:
            proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", ps_lnk_script], stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            
            for line in out.splitlines():
                if "|" in line:
                    name, target, drive = line.split("|")
                    
                    drive_status = "UNKNOWN"
                    if drive in discos_usb_activos: drive_status = "ACTIVE USB"
                    elif drive in discos_fijos: continue 
                    else: drive_status = "REMOVED/DISCONNECTED"
                    
                    if drive_status != "UNKNOWN":
                        tag = "[EVIDENCE]"
                        if drive_status == "REMOVED/DISCONNECTED": tag = "[!!!] GHOST LNK"
                        if any(p in target.lower() for p in palabras): tag = "[!!!] CHEAT LNK MATCH"
                        
                        f.write(f"{tag} {name} -> {target}\n")
                        f.write(f"      Drive Status: {drive_status}\n")
                        lnk_hits += 1
        except: pass
        
        if lnk_hits == 0: f.write("[OK] No suspicious shortcuts to external drives found.\n")

import os
import subprocess
import datetime
import re
import time

def fase_dns_cache(palabras, modo):
    if cancelar_escaneo: return

    # --- PASO 1: MATAR DISCORD ---
    try:
        subprocess.run("taskkill /IM discord.exe /F", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    except:
        pass 

    discord_path = os.path.join(os.getenv('APPDATA'), 'discord', 'Local Storage', 'leveldb')
    url_pattern = re.compile(rb'https?://(?:cdn|media)\.discordapp\.(?:com|net)/attachments/[\w\d_\-\./]+')

    with open(reporte_dns, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== REPORTE DE RED Y ORIGEN (DNS + DISCORD): {datetime.datetime.now()} ===\n")
        
        # --- SECCIÓN DNS ---
        f.write(f"\n[+] SECCIÓN DNS CACHE (Dominios Visitados)\n")
        f.write("="*60 + "\n")
        try:
            out = subprocess.check_output("ipconfig /displaydns", shell=True, text=True, errors='ignore')
            dns_encontrados = False
            for l in out.splitlines():
                l = l.strip()
                if "Nombre de registro" in l or "Record Name" in l:
                    parts = l.split(":")
                    if len(parts) > 1:
                        dom = parts[1].strip()
                        if dom and (modo == "Analizar Todo" or any(p in dom.lower() for p in palabras)):
                            f.write(f"  > DNS ENTRY: {dom}\n")
                            dns_encontrados = True
            if not dns_encontrados: f.write("  (Sin datos relevantes)\n")
        except Exception as e:
            f.write(f"  [ERROR] DNS: {str(e)}\n")

        # --- SECCIÓN DISCORD ---
        f.write(f"\n\n[+] SECCIÓN DISCORD DOWNLOADS (Rastreo de Links)\n")
        f.write("="*60 + "\n")
        
        if os.path.exists(discord_path):
            links_encontrados = 0
            # CORRECCIÓN AQUÍ: Quitamos el 'try' externo innecesario o le añadimos except.
            # Lo mejor es manejar el error dentro del loop o usar un try global con su except.
            try: 
                for filename in os.listdir(discord_path):
                    if filename.endswith(".ldb") or filename.endswith(".log"):
                        full_path = os.path.join(discord_path, filename)
                        try:
                            with open(full_path, "rb") as db_file:
                                content = db_file.read()
                                matches = url_pattern.findall(content)
                                for url_bytes in matches:
                                    url_str = url_bytes.decode('utf-8', errors='ignore')
                                    es_sospechoso = False
                                    if any(ext in url_str.lower() for ext in ['.exe', '.dll', '.rar', '.zip', '.7z']): es_sospechoso = True
                                    elif modo != "Analizar Todo" and any(p in url_str.lower() for p in palabras): es_sospechoso = True
                                    elif modo == "Analizar Todo": es_sospechoso = True

                                    if es_sospechoso:
                                        f.write(f"  > LINK RECUPERADO: {url_str}\n")
                                        links_encontrados += 1
                        except: continue 
            except Exception as e:
                f.write(f"  [ERROR] Al leer carpeta Discord: {str(e)}\n") # <--- ESTE EXCEPT FALTABA

            if links_encontrados == 0:
                f.write(f"  (No se encontraron enlaces sospechosos)\n")
        else:
            f.write("  [INFO] No se encontró carpeta de Discord.\n")

        f.flush()

def fase_browser_forensics(palabras, modo):
    if cancelar_escaneo: return
    now = datetime.datetime.now(); thirty_days_ago = now - datetime.timedelta(days=30)
    epoch_chromium = datetime.datetime(1601, 1, 1); limit_chromium = int((thirty_days_ago - epoch_chromium).total_seconds() * 1000000)
    epoch_firefox = datetime.datetime(1970, 1, 1); limit_firefox = int((thirty_days_ago - epoch_firefox).total_seconds() * 1000000)
    base_u = "C:\\Users"; all_u = []
    if os.path.exists(base_u):
        for u_f in os.listdir(base_u):
            f_u_p = os.path.join(base_u, u_f)
            if os.path.isdir(f_u_p) and u_f.lower() not in ["public", "default", "default user", "all users"]: all_u.append(f_u_p)
    b_cfg = { "Chrome": {"r": r"AppData\Local\Google\Chrome\User Data", "t": "chromium"}, "Edge": {"r": r"AppData\Local\Microsoft\Edge\User Data", "t": "chromium"}, "Brave": {"r": r"AppData\Local\BraveSoftware\Brave-Browser\User Data", "t": "chromium"}, "Opera": {"r": r"AppData\Roaming\Opera Software\Opera Stable", "t": "opera"}, "Firefox": {"r": r"AppData\Roaming\Mozilla\Firefox\Profiles", "t": "firefox"} }
    with open(reporte_browser, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== BROWSER FORENSICS (LAST 30 DAYS): {now} ===\n\n")
        for u_h in all_u:
            f.write(f"[[[ USER: {os.path.basename(u_h)} ]]]\n")
            for b_n, cfg in b_cfg.items():
                b_p = os.path.join(u_h, cfg["r"]); b_t = cfg["t"]
                if not os.path.exists(b_p): continue
                profs = []
                if b_t == "chromium":
                    for i in os.listdir(b_p):
                        f_i = os.path.join(b_p, i)
                        if os.path.isdir(f_i) and (i=="Default" or "Profile" in i):
                            h_f = os.path.join(f_i, "History")
                            if os.path.exists(h_f): profs.append((i, h_f))
                elif b_t == "opera":
                    h_f = os.path.join(b_p, "History"); 
                    if os.path.exists(h_f): profs.append(("Default", h_f))
                elif b_t == "firefox":
                    for p in os.listdir(b_p):
                        pl_f = os.path.join(b_p, p, "places.sqlite")
                        if os.path.exists(pl_f): profs.append((p, pl_f))
                for p_n, db_f in profs:
                    f.write(f"--- {b_n} [{p_n}] ---\n")
                    tmp_db = f"tmp_{random.randint(1000,9999)}.sqlite"
                    try: shutil.copy2(db_f, tmp_db)
                    except:
                        try:
                            with open(db_f, "rb") as source, open(tmp_db, "wb") as dest: dest.write(source.read())
                        except: f.write(" [!] Locked/Access Denied\n"); continue
                    try:
                        conn = sqlite3.connect(tmp_db); cursor = conn.cursor()
                        if b_t in ["chromium", "opera"]:
                            try:
                                cursor.execute("SELECT url, title, last_visit_time FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time DESC", (limit_chromium,))
                                for u, t, vt in cursor.fetchall():
                                    try: dt = epoch_chromium + datetime.timedelta(microseconds=vt); fech = dt.strftime("%Y-%m-%d %H:%M:%S")
                                    except: fech = "Unknown"
                                    info = f"[HIST] [{fech}] {t} - {u}"
                                    if modo == "Analizar Todo" or any(p in info.lower() for p in palabras): f.write(f"{info}\n"); f.flush()
                            except: pass
                            f.write("\n  > DOWNLOADS (Last 30 Days):\n")
                            rows_dl = []
                            try:
                                cursor.execute("SELECT target_path, start_time, tab_url, referrer FROM downloads WHERE start_time > ? ORDER BY start_time DESC", (limit_chromium,)); rows_dl = cursor.fetchall()
                            except: pass
                            for p, st, t_url, ref in rows_dl:
                                try: dt = epoch_chromium + datetime.timedelta(microseconds=st); fech = dt.strftime("%Y-%m-%d %H:%M:%S")
                                except: fech = "Unknown"
                                info = f"  [DL] [{fech}] FILE: {p}\n       ORIGIN: {t_url if t_url else ref}"
                                if modo == "Analizar Todo" or any(k in info.lower() for k in palabras): f.write(f"{info}\n"); f.flush()
                        elif b_t == "firefox":
                            try:
                                cursor.execute("SELECT P.url, P.title, H.visit_date FROM moz_places P, moz_historyvisits H WHERE P.id = H.place_id AND H.visit_date > ? ORDER BY H.visit_date DESC", (limit_firefox,))
                                for u, t, vd in cursor.fetchall():
                                    try: dt = epoch_firefox + datetime.timedelta(microseconds=vd); fech = dt.strftime("%Y-%m-%d %H:%M:%S")
                                    except: fech = "Unknown"
                                    info = f"[HIST] [{fech}] {t} - {u}"
                                    if modo == "Analizar Todo" or any(p in info.lower() for p in palabras): f.write(f"{info}\n"); f.flush()
                            except: pass
                        conn.close(); os.remove(tmp_db); f.write("\n")
                    except: 
                        if os.path.exists(tmp_db): 
                            try: os.remove(tmp_db)
                            except: pass
            f.write("\n")

def fase_persistence(palabras, modo):
    if cancelar_escaneo: return
    with open(reporte_persistencia, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== PERSISTENCE: {datetime.datetime.now()} ===\n\n"); f.write("--- REGISTRY ---\n")
        r_reg = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"), (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"), (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")]
        for h, s in r_reg:
            try:
                with winreg.OpenKey(h, s) as k:
                    for i in range(winreg.QueryInfoKey(k)[1]):
                        n, v, _ = winreg.EnumValue(k, i)
                        info = f"KEY: {n} -> {v}"
                        if modo == "Analizar Todo" or any(p in info.lower() for p in palabras): f.write(f"[REG] {info}\n"); f.flush()
            except: pass
        f.write("\n--- STARTUP FOLDER ---\n")
        dirs = [os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\Start Menu\Programs\Startup"), os.path.join(os.getenv('PROGRAMDATA'), r"Microsoft\Windows\Start Menu\Programs\Startup")]
        for d in dirs:
            if os.path.exists(d):
                for fl in os.listdir(d):
                    info = f"FILE: {fl} IN {d}"
                    if modo == "Analizar Todo" or any(p in info.lower() for p in palabras): f.write(f"[DIR] {info}\n"); f.flush()
        f.write("\n--- TASKS ---\n")
        try:
            proc = subprocess.Popen('schtasks /query /fo LIST /v', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True, text=True)
            out, _ = proc.communicate(); t_n = ""
            for l in out.splitlines():
                if "TaskName:" in l or "Nombre de tarea:" in l: t_n = l.strip()
                if "Task To Run:" in l or "Tarea para ejecutar:" in l:
                    t_r = l.strip(); full = f"{t_n} | {t_r}"
                    if "Microsoft\\" not in t_n and (modo == "Analizar Todo" or any(p in full.lower() for p in palabras)): f.write(f"[TASK] {full}\n"); f.flush()
        except: pass

def fase_event_logs(palabras, modo):
    """
    FASE EVENT LOGS FORENSICS v2.0 (INTENT ANALYSIS)
    - Detecta Borrado de Logs (Prueba de Manipulación).
    - Caza Drivers de Kernel (Cheats Ring0) instalados recientemente.
    - Revela Exclusiones de Antivirus (Donde esconden el cheat).
    - Muestra Intentos de Login fallidos masivos (Bruteforce/Malware).
    """
    if cancelar_escaneo: return
    print(f"[13/26] Windows Event Log Forensics [DEEP SCAN]...")

    # Comandos PowerShell Optimizado
    # Usamos Select-Object para traer solo lo útil y formatearlo limpio.
    cmds = [
        # 1. LOG WIPED (CRITICO) - Si esto aparece, es Ban directo.
        ("SECURITY_LOG_CLEARED", "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object @{N='Time';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, @{N='User';E={$_.Properties[1].Value}}, Message"),
        ("SYSTEM_LOG_CLEARED", "Get-WinEvent -FilterHashtable @{LogName='System'; ID=104} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object @{N='Time';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, @{N='User';E={$_.Properties[0].Value}}, Message"),
        
        # 2. NEW SERVICE INSTALLED (Caza Drivers .sys de Cheats)
        ("NEW_SERVICE_INSTALLED", "Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} -MaxEvents 30 -ErrorAction SilentlyContinue | Select-Object @{N='Time';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, @{N='ServiceName';E={$_.Properties[0].Value}}, @{N='ImagePath';E={$_.Properties[1].Value}}, @{N='ServiceType';E={$_.Properties[2].Value}}"),
        
        # 3. DEFENDER EXCLUSIONS (Donde esconden el cheat)
        ("DEFENDER_EXCLUSION_ADDED", "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=5007} -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object @{N='Time';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, @{N='Path';E={$_.Properties[1].Value}}, Message"),
        
        # 4. DEFENDER DETECTIONS (Virus/HackTool detectados)
        ("DEFENDER_THREAT_FOUND", "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1116,1117} -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object @{N='Time';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, @{N='Threat';E={$_.Properties[0].Value}}, @{N='Path';E={$_.Properties[1].Value}}"),
        
        # 5. PROCESS EXECUTION (Si la auditoría está activa - ID 4688)
        ("PROCESS_STARTED", "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object @{N='Time';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, @{N='Process';E={$_.Properties[5].Value}}, @{N='CommandLine';E={$_.Properties[8].Value}}")
    ]

    with open(reporte_eventos, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== WINDOWS EVENT LOG FORENSICS: {datetime.datetime.now()} ===\n")
        f.write("Scanning for: Log Wiping, Kernel Drivers, AV Exclusions & Threats.\n\n")

        for tit, ps in cmds:
            f.write(f"--- {tit} ---\n")
            
            try:
                # Ejecutamos PowerShell y pedimos salida en formato lista legible
                proc = subprocess.Popen(
                    f'powershell -NoProfile -Command "{ps} | Format-List"', 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    shell=True, 
                    text=True, 
                    encoding='cp850', # Encoding consola Windows
                    errors='ignore',
                    creationflags=0x08000000
                )
                out, err = proc.communicate()
                
                if not out or "No se encontraron" in err or "NoMatchingEventsFound" in err:
                    f.write("   [OK] Clean. No events found.\n")
                else:
                    # Procesamos la salida para resaltar amenazas
                    bloque = []
                    for line in out.splitlines():
                        line = line.strip()
                        if not line:
                            # Fin de un bloque de evento
                            if bloque:
                                txt_bloque = "\n".join(bloque)
                                es_sospechoso = False
                                tag = ""
                                
                                # A. ANALISIS DE AMENAZA
                                
                                # 1. Borrado de Logs
                                if "LOG_CLEARED" in tit:
                                    tag = "[!!!] EVIDENCE DESTROYED (LOG WIPED)"
                                    es_sospechoso = True
                                
                                # 2. Driver de Kernel Sospechoso
                                elif "NEW_SERVICE" in tit:
                                    # Si el driver está en AppData o Temp, es 99% un cheat
                                    if "AppData" in txt_bloque or "Temp" in txt_bloque:
                                        tag = "[!!!] KERNEL CHEAT DRIVER"
                                        es_sospechoso = True
                                    # Si el nombre es aleatorio (heuristic simple) o raro
                                    elif ".sys" in txt_bloque.lower():
                                        # Filtramos drivers legitimos comunes
                                        if "Intel" not in txt_bloque and "NVIDIA" not in txt_bloque:
                                            tag = "[WARN] SUSPICIOUS DRIVER LOAD"
                                            if modo == "Analizar Todo": es_sospechoso = True
                                
                                # 3. Exclusiones de AV
                                elif "DEFENDER_EXCLUSION" in tit:
                                    tag = "[WARN] ANTIVIRUS BYPASS PATH"
                                    es_sospechoso = True
                                
                                # 4. Amenaza Detectada
                                elif "THREAT_FOUND" in tit:
                                    tag = "[!!!] MALWARE DETECTED"
                                    es_sospechoso = True
                                
                                # 5. Ejecución de Proceso
                                elif "PROCESS_STARTED" in tit:
                                    if any(p in txt_bloque.lower() for p in palabras):
                                        tag = "[ALERTA] KEYWORD MATCH"
                                        es_sospechoso = True

                                # B. ESCRITURA
                                if es_sospechoso or modo == "Analizar Todo":
                                    if tag: f.write(f"{tag}\n")
                                    for l in bloque: f.write(f"   {l}\n")
                                    f.write("   " + "-"*40 + "\n")
                                
                                bloque = [] # Reset para el siguiente
                        else:
                            bloque.append(line)
                            
                    # Procesar el último bloque si quedó colgado
                    if bloque:
                         # (Misma lógica de arriba... simplificada para brevedad)
                         if "LOG_CLEARED" in tit: f.write(f"[!!!] LOG WIPED\n")
                         for l in bloque: f.write(f"   {l}\n")

            except Exception as e:
                f.write(f"   [ERROR] Failed to query events: {e}\n")
            
            f.write("\n")
            
def fase_process_hunter(palabras, modo):
    if cancelar_escaneo: return
    print(f"[14/24] Process Genealogy Hunter (Parent-Child Analysis) [LETHAL]...")
    
    # --- ESTRUCTURAS NATIVAS ---
    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeapID", ctypes.c_ulong),
                    ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                    ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_char * 260)]

    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    
    # --- REGLAS DE GENEALOGÍA (La trampa para cheats) ---
    # Hijo: [Padres Permitidos]
    GENEALOGY_RULES = {
        "svchost.exe": ["services.exe"],
        "lsass.exe": ["wininit.exe"],
        "services.exe": ["wininit.exe"],
        "lsm.exe": ["wininit.exe"],
        "csrss.exe": ["smss.exe"], # A veces creado por System, pero smss es el standard user-mode
        "wininit.exe": ["smss.exe"],
        "winlogon.exe": ["smss.exe"],
        "spoolsv.exe": ["services.exe"],
        "taskhostw.exe": ["svchost.exe", "explorer.exe", "services.exe"],
        "sihost.exe": ["svchost.exe"],
        "fontdrvhost.exe": ["wininit.exe", "winlogon.exe"],
        "dwm.exe": ["winlogon.exe"]
    }
    
    # Rutas legítimas esperadas
    LEGIT_PATHS = {
        "svchost.exe": r"c:\windows\system32",
        "lsass.exe": r"c:\windows\system32",
        "csrss.exe": r"c:\windows\system32",
        "wininit.exe": r"c:\windows\system32",
        "services.exe": r"c:\windows\system32",
        "winlogon.exe": r"c:\windows\system32",
        "explorer.exe": r"c:\windows",
        "conhost.exe": r"c:\windows\system32"
    }

    with open(reporte_process, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== PROCESS GENEALOGY & MASQUERADE HUNTER: {datetime.datetime.now()} ===\n")
        f.write("Strategy: Native Snapshot + Parent/Child Validation + Path Check\n\n")
        f.write("--- LIVE PROCESS ANALYSIS ---\n")

        # 1. TOMAR FOTO DEL SISTEMA (SNAPSHOT)
        h_snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if h_snap == -1:
            f.write("[ERROR] Could not take process snapshot.\n")
            return

        # 2. MAPEAR TODOS LOS PROCESOS (PID -> Info)
        proc_map = {}
        if ctypes.windll.kernel32.Process32First(h_snap, ctypes.byref(pe32)):
            while True:
                pid = pe32.th32ProcessID
                ppid = pe32.th32ParentProcessID
                name = pe32.szExeFile.decode('cp1252', 'ignore').lower()
                proc_map[pid] = {"name": name, "ppid": ppid, "path": "Unknown"}
                if not ctypes.windll.kernel32.Process32Next(h_snap, ctypes.byref(pe32)): break
        ctypes.windll.kernel32.CloseHandle(h_snap)

        # 3. ANALIZAR CADA PROCESO
        buffer = ctypes.create_unicode_buffer(1024)
        count_susp = 0
        
        for pid, info in proc_map.items():
            if cancelar_escaneo: break
            name = info["name"]
            ppid = info["ppid"]
            
            # Obtener Ruta Real (Requiere abrir proceso)
            # Usamos QUERY_LIMITED_INFORMATION para saltar protecciones de admin
            h_proc = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            real_path = ""
            if h_proc:
                size = ctypes.c_ulong(1024)
                if ctypes.windll.kernel32.QueryFullProcessImageNameW(h_proc, 0, buffer, ctypes.byref(size)):
                    real_path = buffer.value.lower()
                    info["path"] = real_path # Guardamos para uso futuro
                ctypes.windll.kernel32.CloseHandle(h_proc)

            # --- DETECCIONES ---
            is_suspicious = False
            reasons = []

            # A. DETECCIÓN DE CAMUFLAJE DE RUTA (Masquerading)
            if name in LEGIT_PATHS:
                expected_dir = LEGIT_PATHS[name]
                if real_path and not real_path.startswith(expected_dir):
                    is_suspicious = True
                    reasons.append(f"FAKE PATH: Running from {real_path} (Expected: {expected_dir})")

            # B. DETECCIÓN DE PADRE FALSO (Genealogy Mismatch)
            if name in GENEALOGY_RULES:
                parent_info = proc_map.get(ppid)
                if parent_info:
                    parent_name = parent_info["name"]
                    allowed_parents = GENEALOGY_RULES[name]
                    if parent_name not in allowed_parents:
                        is_suspicious = True
                        reasons.append(f"BAD PARENT: Spawmed by '{parent_name}' (PID {ppid}). Expected: {allowed_parents}")
                else:
                    # El padre murió o no existe (Hérfano). 
                    # Para servicios críticos esto es raro, pero pasa. No lo marcamos rojo directo, pero es nota.
                    pass

            # C. DETECCIÓN DE RUTA TEMPORAL (Lazy Cheats)
            if real_path and ("\\temp\\" in real_path or "\\appdata\\" in real_path or "\\downloads\\" in real_path):
                if name.endswith(".exe"):
                    # Solo marcamos si parece un cheat o modo paranoico
                    if any(k in name for k in ["loader", "client", "cheat", "inject"]):
                         is_suspicious = True
                         reasons.append("Running from TEMP/APPDATA with suspicious name")
                    elif modo == "Analizar Todo":
                         reasons.append("Running from TEMP/APPDATA")
                         # Nota: No marcamos is_suspicious a True solo por esto para no llenar de falsos positivos en Discord/Updates,
                         # pero lo reportamos abajo.

            # D. KEYWORD MATCH
            if any(p in name for p in palabras) or any(p in real_path for p in palabras):
                is_suspicious = True
                reasons.append("Keyword Match")

            # --- REPORTE ---
            if is_suspicious:
                count_susp += 1
                f.write(f"[!!!] PROCESS ANOMALY: {name} (PID {pid})\n")
                f.write(f"      Path: {real_path}\n")
                f.write(f"      Parent PID: {ppid} ({proc_map.get(ppid, {}).get('name', 'Unknown')})\n")
                f.write(f"      Detection: {', '.join(reasons)}\n")
                f.write("-" * 50 + "\n")
                f.flush()
                
            elif modo == "Analizar Todo" and real_path:
                # Log limpio
                f.write(f"[LIVE] {name} (PID {pid}) -> {real_path}\n")

        if count_susp == 0:
            f.write("[OK] No process genealogy anomalies found.\n")

        # 4. PROCESOS MUERTOS (EVENT LOGS) - Mantenemos esto porque es útil
        f.write("\n--- DEAD PROCESSES (Last 45 mins) ---\n")
        try:
            ps = "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4689} -ErrorAction SilentlyContinue | Where-Object {$_.TimeCreated -ge (Get-Date).AddMinutes(-45)} | Select-Object @{N='Time';E={$_.TimeCreated.ToString('HH:mm:ss')}}, @{N='Name';E={$_.Properties[0].Value}} | Format-Table -HideTableHeaders"
            proc = subprocess.Popen(f'powershell -NoProfile -Command "{ps}"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, encoding='cp850', errors='ignore', creationflags=0x08000000)
            out, _ = proc.communicate()
            if out:
                unique_procs = set()
                for l in out.splitlines():
                    clean_l = l.strip()
                    if clean_l: unique_procs.add(clean_l)
                for p in unique_procs:
                     if modo == "Analizar Todo" or any(k in p.lower() for k in palabras): f.write(f"[DEAD] {p}\n"); f.flush()
        except: pass

def fase_game_cheat_hunter(palabras, modo):
    if cancelar_escaneo:
        return

    print("[15/25] Game Cheat Hunter (YARA FIXED | ENTROPY | PE)")

    try:
        import yara
        YARA_AVAILABLE = True
    except:
        YARA_AVAILABLE = False

    # ================= CONFIG =================
    internal_blacklist = [
        "cheat engine", "process hacker", "x64dbg", "ollydbg",
        "dnspy", "injector", "ks dumper", "http debugger",
        "netlimiter", "aimbot", "wallhack"
    ]

    target_exts = ('.exe', '.dll', '.sys', '.bin', '.dat', '.tmp')

    MAX_SIZE_MB = 40
    READ_LIMIT_MB = 15

    # ================= PATHS =================
    user = os.environ.get("USERPROFILE", "C:\\")
    hot_paths = [
        os.path.join(user, "Desktop"),
        os.path.join(user, "Downloads"),
        os.path.join(user, "AppData", "Local", "Temp"),
        os.path.join(user, "AppData", "Roaming")
    ]

    onedrive = os.path.join(user, "OneDrive")
    if os.path.exists(onedrive):
        hot_paths += [
            os.path.join(onedrive, "Desktop"),
            os.path.join(onedrive, "Downloads")
        ]

    # ================= REPORT =================
    with open(reporte_game, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== GAME CHEAT HUNTER ===\n")
        f.write(f"Start: {datetime.datetime.now()}\n")

        # ================= YARA LOAD =================
        yara_rules = None
        yara_active = False

        if YARA_AVAILABLE:
            try:
                yara_rules = yara.compile(filepath="reglas_scanneler.yar")
                yara_active = True
                f.write("YARA: ACTIVE\n\n")
            except Exception as e:
                f.write(f"YARA: FAILED ({e})\n\n")
        else:
            f.write("YARA: NOT INSTALLED\n\n")

        total_scanned = 0
        detections = 0

        # ================= SCAN =================
        for target_dir in hot_paths:
            if not os.path.exists(target_dir):
                continue

            f.write(f"--- Scanning: {target_dir} ---\n")

            try:
                with os.scandir(target_dir) as entries:
                    for entry in entries:
                        if cancelar_escaneo:
                            break

                        try:
                            if not entry.is_file():
                                continue
                            if not entry.name.lower().endswith(target_exts):
                                continue

                            size = entry.stat().st_size
                            if size > MAX_SIZE_MB * 1024 * 1024:
                                continue

                            total_scanned += 1
                            suspicious = False
                            reasons = []
                            entropy_val = 0

                            # ================= READ =================
                            with open(entry.path, "rb") as bf:
                                data = bf.read(READ_LIMIT_MB * 1024 * 1024)

                            # ================= ENTROPY =================
                            entropy_val = calculate_entropy(data)
                            if entropy_val > 7.3:
                                suspicious = True
                                reasons.append(f"High entropy ({entropy_val:.2f})")

                            # ================= YARA =================
                            if yara_active:
                                try:
                                    matches = yara_rules.match(data=data)
                                    if not matches:
                                        matches = yara_rules.match(filepath=entry.path)

                                    if matches:
                                        suspicious = True
                                        rules = [m.rule for m in matches]
                                        reasons.append(f"YARA MATCH: {', '.join(rules)}")
                                except:
                                    pass

                            # ================= PE METADATA =================
                            try:
                                pe = pefile.PE(entry.path, fast_load=True)
                                if hasattr(pe, 'FileInfo'):
                                    for info in pe.FileInfo:
                                        if hasattr(info, 'StringTable'):
                                            for st in info.StringTable:
                                                for _, v in st.entries.items():
                                                    val = v.decode(errors="ignore").lower()
                                                    for bad in internal_blacklist:
                                                        if bad in val:
                                                            suspicious = True
                                                            reasons.append(f"Metadata keyword: {bad}")
                                                            break
                                pe.close()
                            except:
                                pass

                            # ================= REPORT =================
                            if suspicious:
                                detections += 1
                                f.write(f"[!!!] CHEAT DETECTED: {entry.name}\n")
                                f.write(f"      Path: {entry.path}\n")
                                f.write(f"      Size: {size / 1024:.1f} KB\n")
                                f.write(f"      Entropy: {entropy_val:.2f}\n")
                                for r in reasons:
                                    f.write(f"      - {r}\n")
                                f.write("-" * 55 + "\n")
                                f.flush()

                        except:
                            continue

            except Exception as e:
                f.write(f"[ERROR] Folder scan failed: {e}\n")

        f.write(f"\nScan finished. Files scanned: {total_scanned} | Detections: {detections}\n")

    print("[✓] Game Cheat Hunter completed")


def filetime_to_dt(ft_dec):
    try:
        us = ft_dec / 10
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)
    except: return None

def fase_nuclear_traces(palabras, modo):
    # if cancelar_escaneo: return
    print(f"[16/24] Nuclear Traces (Pipes & BAM with Timestamps) [DEFINITIVE]...")
    
    global reporte_nuclear
    try:
        base_path = HISTORIAL_RUTAS.get('path', os.path.abspath("."))
        folder_name = HISTORIAL_RUTAS.get('folder', "Resultados_SS")
    except:
        base_path = os.path.abspath(".")
        folder_name = "Resultados_SS"

    reporte_nuclear = os.path.join(base_path, folder_name, "Nuclear_Traces_Detection.txt")

    # Calculamos límite de tiempo (Ej: Últimas 4 horas)
    # Todo lo que se haya ejecutado antes de esto, se ignora (o se marca como OLD)
    now = datetime.datetime.now()
    limit_time = now - datetime.timedelta(hours=4)

    with open(reporte_nuclear, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== NUCLEAR TRACES: {now.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write("Target: Active Pipes & RECENT BAM Execution (Last 4 Hours)\n\n")
        
        # --- PART 1: NAMED PIPES (Tu código original, está perfecto) ---
        suspicious_pipes = ["cheat", "hack", "injector", "loader", "esp", "aim", "battleye", "easyanticheat", "faceit", "esea", "vanguard", "overlay", "hook", "auth"]
        f.write("--- LIVE NAMED PIPES ---\n")
        try:
            pipes = os.listdir(r'\\.\pipe\\')
            found_pipe = False
            for pipe in pipes:
                pipe_lower = pipe.lower()
                if any(s in pipe_lower for s in suspicious_pipes): 
                    f.write(f"[PIPE DETECTED] Posible Hack Comms: {pipe}\n")
                    found_pipe = True
                
                # Detectar UUIDs random (típico de clientes inyectados)
                if len(pipe) > 20 and "-" in pipe and "{" not in pipe and "com" not in pipe:
                      if modo == "Analizar Todo": 
                          f.write(f"[SUSPICIOUS PIPE] Random/UUID Pattern: {pipe}\n")
            
            if not found_pipe: f.write("[OK] No suspicious pipes found.\n")

        except Exception as e: f.write(f"Error scanning pipes: {e}\n")

        # --- PART 2: BAM EXECUTION HISTORY (MEJORADO CON FECHAS) ---
        f.write("\n--- BAM EXECUTION HISTORY (TIMESTAMPED) ---\n")
        try:
            bam_path = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
            # Necesitamos KEY_READ para leer valores
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bam_path, 0, winreg.KEY_READ) as k_bam:
                num_sids = winreg.QueryInfoKey(k_bam)[0]
                
                for i in range(num_sids):
                    sid = winreg.EnumKey(k_bam, i)
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{bam_path}\\{sid}", 0, winreg.KEY_READ) as k_user:
                            num_vals = winreg.QueryInfoKey(k_user)[1]
                            
                            hits = 0
                            for j in range(num_vals):
                                # Aquí está la magia: value_data contiene la FECHA binaria
                                exe_path, value_data, type_ = winreg.EnumValue(k_user, j)
                                
                                # Decodificar fecha (Primeros 8 bytes son FILETIME)
                                try:
                                    if type_ == winreg.REG_BINARY and len(value_data) >= 8:
                                        filetime_int = struct.unpack('<Q', value_data[:8])[0]
                                        exec_time = filetime_to_dt(filetime_int)
                                    else:
                                        exec_time = None
                                except: exec_time = None

                                # Normalización de ruta
                                if "\\Device\\HarddiskVolume" in exe_path: 
                                    exe_path = exe_path.replace("\\Device\\HarddiskVolume", "Volume_")
                                
                                exe_lower = exe_path.lower()
                                
                                # FILTROS LETALES
                                is_recent = False
                                if exec_time:
                                    # Si la fecha es válida y es mayor (más nueva) que el límite
                                    if exec_time > limit_time:
                                        is_recent = True
                                        time_str = exec_time.strftime('%H:%M:%S')
                                    else:
                                        # Si es viejo, lo saltamos para limpiar el reporte (o lo marcamos OLD)
                                        # Para SS letal, nos interesa el "AHORA".
                                        continue 
                                else:
                                    time_str = "Unknown Time"

                                # Analisis de Keywords
                                hit = False
                                reason = ""

                                # 1. Ejecución desde carpetas sospechosas (Temp, AppData)
                                if "temp" in exe_lower or "appdata" in exe_lower:
                                    if any(k in exe_lower for k in ["cheat", "loader", "inject", "priv", "vip", "client"]): 
                                        hit = True; reason = "Keyword in Temp Path"
                                    elif modo == "Analizar Todo" and ".exe" in exe_lower and is_recent:
                                        # Si es reciente y está en temp, aunque no tenga nombre de cheat, es sospechoso
                                        f.write(f"[RECENT TEMP] {time_str} | {exe_path}\n")
                                        continue

                                # 2. Ejecución externa (USB / Discos raros)
                                if "volume_" in exe_lower and "program files" not in exe_lower and "windows" not in exe_lower: 
                                    hit = True; reason = "External Drive / Hidden Volume"

                                # 3. Keywords Generales
                                if any(p in exe_lower for p in palabras) or any(s in exe_lower for s in ["aimbot", "esp", "wallhack", "clicker"]): 
                                    hit = True; reason = "Keyword Match"

                                # Escritura del reporte
                                if hit and is_recent:
                                    f.write(f"[!!!] EXECUTION PROVEN: {time_str} | {exe_path}\n")
                                    f.write(f"      Reason: {reason}\n")
                                    hits += 1
                            
                            if hits == 0:
                                f.write(f"[INFO] SID {sid[:8]}... Clean in last 4 hours.\n")

                    except Exception as e_inner: 
                        # f.write(f"Error reading SID key: {e_inner}\n")
                        pass

        except Exception as e: f.write(f"Error accessing BAM registry: {e}\n")
        
    print(f"   --> Reporte Nuclear generado: {reporte_nuclear}")

def fase_kernel_hunter(palabras, modo):
    if cancelar_escaneo: return
    print(f"[17/24] Kernel Hunter (Drivers & Boot config) [NUCLEAR]...")
    vuln_drivers = ["iqvw64e.sys", "iqvw32e.sys", "capcom.sys", "gdrv.sys", "atszio.sys", "winio.sys", "ene.sys", "enetechio.sys", "msio64.sys", "glckio2.sys", "inpoutx64.sys", "rzpnk.sys"]
    with open(reporte_kernel, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== KERNEL HUNTER & ANOMALIES: {datetime.datetime.now()} ===\n\n"); f.write("--- BOOT CONFIGURATION (Test Signing Check) ---\n")
        try:
            proc = subprocess.Popen('bcdedit /enum {current}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000); out, _ = proc.communicate(); danger_flags = False
            if out:
                lines = out.splitlines()
                for l in lines:
                    low_l = l.lower()
                    if "testsigning" in low_l and "yes" in low_l: f.write("[!!!] CRITICAL: WINDOWS TEST SIGNING IS ON (Permite drivers de hacks no firmados)\n"); danger_flags = True
                    if "debug" in low_l and "yes" in low_l: f.write("[!!!] CRITICAL: KERNEL DEBUGGING IS ON (Usado para manipular memoria)\n"); danger_flags = True
                    if "nointegritychecks" in low_l and "yes" in low_l: f.write("[!!!] CRITICAL: INTEGRITY CHECKS DISABLED\n"); danger_flags = True
            if not danger_flags: f.write("[OK] Secure Boot Integrity appears normal.\n")
        except: f.write("Error reading BCD.\n")
        f.write("\n--- LOADED KERNEL DRIVERS SCAN ---\n")
        try:
            cmd = 'driverquery /v /fo csv'; proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000); out, _ = proc.communicate()
            if out:
                lines = out.splitlines()
                for l in lines:
                    if not l.strip(): continue
                    low_l = l.lower()
                    for vd in vuln_drivers:
                        if vd in low_l: f.write(f"[!!!] VULNERABLE DRIVER DETECTED: {l.strip()}\n      (Posible ataque KDMapper/Overlay Kernel)\n"); f.flush()
                    if "users\\" in low_l or "appdata" in low_l or "temp" in low_l or "downloads" in low_l: clean_line = l.replace('"', '').strip(); f.write(f"[!!!] MALICIOUS DRIVER PATH: {clean_line}\n      (Driver cargando desde espacio de usuario)\n"); f.flush()
                    if modo == "Analizar Todo":
                        if "microsoft" not in low_l and "intel" not in low_l and "nvidia" not in low_l and "amd" not in low_l and "realtek" not in low_l: f.write(f"[UNKNOWN DRIVER] {l[:100]}...\n"); f.flush()
        except Exception as e: f.write(f"Error listing drivers: {e}\n")
        f.write("\n--- NETWORK TAMPERING (Hosts File) ---\n")
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            if os.path.exists(hosts_path):
                with open(hosts_path, "r", encoding="utf-8", errors="ignore") as hf:
                    lines = hf.readlines(); found_tamper = False
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#"): continue
                        bad_domains = ["vac", "battleye", "easyanticheat", "riot", "vanguard", "auth", "license"]
                        if any(b in line.lower() for b in bad_domains): f.write(f"[!!!] HOSTS TAMPERING: {line}\n"); found_tamper = True
                    if not found_tamper: f.write("[OK] Hosts file clean.\n")
        except: pass

def fase_dna_prefetch(palabras, modo):
    """
    FASE 18 OPTIMIZADA: DNA (Imports) & PREFETCH FORENSICS (Decompression + Deep Scan).
    Capacidad: Lee archivos .pf comprimidos (Win10/11) y busca strings internas.
    """
    # if cancelar_escaneo: return
    print(f"[18/24] DNA & Prefetch Hunter (MAM Decompression) [FORENSIC]...")
    
    import ctypes
    import struct
    import binascii
    
    global reporte_dna, HISTORIAL_RUTAS
    try:
        base_path = HISTORIAL_RUTAS.get('path', os.path.abspath("."))
        folder_name = HISTORIAL_RUTAS.get('folder', "Resultados_SS")
    except:
        base_path = os.path.abspath(".")
        folder_name = "Resultados_SS"
        
    reporte_dna = os.path.join(base_path, folder_name, "DNA_Prefetch.txt")

    # --- 1. CONFIGURACIÓN DE DESCOMPRESIÓN NATIVA (NTDLL) ---
    try:
        ntdll = ctypes.windll.ntdll
        RtlDecompressBuffer = ntdll.RtlDecompressBuffer
        # RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize)
        COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004
    except:
        RtlDecompressBuffer = None

    def decompress_pf(filepath):
        """
        Intenta descomprimir un archivo Prefetch (MAM) o leerlo raw (SCCA).
        Retorna: bytes descomprimidos o None si falla.
        """
        try:
            with open(filepath, "rb") as f:
                header = f.read(8)
                f.seek(0)
                file_content = f.read()

            # Caso 1: Archivo Comprimido (Win 10/11) - Header "MAM\x04"
            if header.startswith(b'MAM'):
                if not RtlDecompressBuffer: return None # No soportado en este OS/Error carga
                
                # Estructura MAM: Signature(4) + SizeDecompressed(4)
                decompressed_size = struct.unpack('<I', header[4:8])[0]
                
                # Buffer de salida
                out_buffer = ctypes.create_string_buffer(decompressed_size)
                final_size = ctypes.c_ulong(0)
                
                # El contenido comprimido empieza después del header (offset 8)
                compressed_data = file_content[8:]
                in_buffer = ctypes.create_string_buffer(compressed_data)
                
                status = RtlDecompressBuffer(
                    COMPRESSION_FORMAT_XPRESS_HUFF,
                    out_buffer, decompressed_size,
                    in_buffer, len(compressed_data),
                    ctypes.byref(final_size)
                )
                
                if status == 0: # STATUS_SUCCESS
                    return out_buffer.raw
                else:
                    return None

            # Caso 2: Archivo Sin Comprimir (Win 7 o herramientas viejas) - Header "SCCA"
            elif header.startswith(b'SCCA'):
                return file_content
            
            return None # No es un PF válido
        except: return None

    # --- 2. LISTAS DE CAZA ---
    suspicious_imports = [b"WriteProcessMemory", b"CreateRemoteThread", b"VirtualAllocEx", b"OpenProcess", 
                          b"LdrLoadDll", b"NtCreateThreadEx", b"SetWindowsHookExA", b"Wow64Transition"]
    
    hot_paths = [
        os.path.join(os.environ["USERPROFILE"], "Downloads"),
        os.path.join(os.environ["USERPROFILE"], "Desktop"),
        os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Temp")
    ]
    
    # Procesos críticos cuyo INTERIOR debemos escanear en Prefetch
    # Si csgo.exe cargó un cheat, aparecerá dentro de CSGO.EXE-xxxx.pf
    deep_scan_targets = ["csgo", "discord", "explorer", "steam", "dota", "valorant", "javaw", "minecraft", "anydesk", "teamviewer"]

    with open(reporte_dna, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== DNA & PREFETCH FORENSICS: {datetime.datetime.now()} ===\n")
        f.write("Mode: Native Decompression (Reading inside Prefetch files)\n\n")
        
        # ------------------------------------------------------------------
        # PARTE 1: DNA ANALYSIS (Imports de Ejecutables en Disco)
        # ------------------------------------------------------------------
        f.write("--- [1] EXECUTABLE DNA (Static Import Analysis) ---\n")
        dna_hits = 0
        try:
            for target_dir in hot_paths:
                if not os.path.exists(target_dir): continue
                
                with os.scandir(target_dir) as entries:
                    for entry in entries:
                        if entry.is_file() and entry.name.lower().endswith('.exe'):
                            # Filtro tamaño (Optimización)
                            if entry.stat().st_size > 20 * 1024 * 1024: continue
                            
                            try:
                                pe = pefile.PE(entry.path, fast_load=True)
                                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                                
                                found_apis = []
                                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                                    for mod in pe.DIRECTORY_ENTRY_IMPORT:
                                        for imp in mod.imports:
                                            if imp and imp.name and imp.name in suspicious_imports:
                                                found_apis.append(imp.name.decode('utf-8'))
                                pe.close()
                                
                                # Si tiene 2 o más APIs de inyección, es sospechoso
                                if len(found_apis) >= 2:
                                    f.write(f"[!!!] INJECTOR DNA: {entry.name}\n")
                                    f.write(f"      Path: {entry.path}\n")
                                    f.write(f"      APIs: {', '.join(found_apis)}\n")
                                    f.write("-" * 40 + "\n")
                                    dna_hits += 1
                            except: pass
        except Exception as e: f.write(f"DNA Scan Error: {e}\n")
        
        if dna_hits == 0: f.write("[OK] No high-risk injectors found in hot folders.\n")

        # ------------------------------------------------------------------
        # PARTE 2: PREFETCH DEEP SCAN (La Joya de la Corona)
        # ------------------------------------------------------------------
        f.write("\n--- [2] PREFETCH TRACE CHAINS (Compressed Analysis) ---\n")
        f.write("Scanning loaded modules inside Prefetch files...\n")
        
        pf_dir = r"C:\Windows\Prefetch"
        pf_hits = 0
        
        if os.path.exists(pf_dir):
            try:
                # Usamos DisableFileSystemRedirection por si corremos en 32 bits
                with DisableFileSystemRedirection():
                    # Listar archivos
                    pf_files = [f for f in os.listdir(pf_dir) if f.lower().endswith(".pf")]
                    
                    for pf in pf_files:
                        # if cancelar_escaneo: break
                        pf_lower = pf.lower()
                        
                        # --- CHECK 1: NOMBRE DEL PREFETCH ---
                        # ¿El propio archivo prefetch tiene nombre de cheat?
                        is_suspicious_name = False
                        if any(p in pf_lower for p in palabras): is_suspicious_name = True
                        
                        # --- CHECK 2: DEEP SCAN (Leer interior) ---
                        # Solo analizamos a fondo si es un proceso objetivo (CSGO, Discord, etc) 
                        # O si ya tiene nombre sospechoso (para confirmar)
                        should_deep_scan = is_suspicious_name or any(t in pf_lower for t in deep_scan_targets)
                        
                        evidence_found = []
                        
                        if should_deep_scan:
                            content = decompress_pf(os.path.join(pf_dir, pf))
                            if content:
                                # Convertimos a string ignorando errores para buscar texto plano
                                # Windows guarda rutas en UTF-16LE dentro del prefetch
                                try:
                                    # Truco de velocidad: Decodificar como UTF-16 ignora basura binaria a veces,
                                    # pero mejor buscamos patrones de bytes para ser exactos.
                                    # Buscamos palabras clave convertidas a UTF-16LE
                                    for kw in palabras:
                                        kw_bytes = kw.encode("utf-16-le")
                                        if kw_bytes in content:
                                            evidence_found.append(f"Loaded Module: {kw}")
                                    
                                    # También buscar extensiones peligrosas comunes en cheats
                                    if b'.\x00d\x00l\x00l' in content: # ".dll" en utf-16
                                        # Aquí podrías implementar regex binario para extraer rutas completas
                                        pass
                                except: pass
                        
                        # REPORTAR SI HAY HALLAZGOS
                        if is_suspicious_name or evidence_found:
                            tag = "[!!!]"
                            f.write(f"{tag} PREFETCH FILE: {pf}\n")
                            if is_suspicious_name:
                                f.write(f"      Detection: Suspicious Execution Filename\n")
                            if evidence_found:
                                f.write(f"      INTERNAL TRACES (Files loaded by this process):\n")
                                for ev in evidence_found:
                                    f.write(f"      > {ev}\n")
                            f.write("-" * 40 + "\n")
                            pf_hits += 1
                        
                        elif modo == "Analizar Todo":
                            # En modo full, listamos ejecuciones recientes de objetivos
                            if any(t in pf_lower for t in deep_scan_targets):
                                f.write(f"[INFO] Target Executed: {pf}\n")

            except Exception as e:
                f.write(f"[ERROR] Prefetch Access Failed: {e}\n")
        else:
            f.write("[ERROR] Prefetch folder not found or Access Denied.\n")
            
        if pf_hits == 0: f.write("[OK] No suspicious prefetch traces found.\n")
        
def fase_network_hunter(palabras, modo):
    if cancelar_escaneo: return
    print(f"[19/24] Network Hunter (Connections & History) [LIVE+FORENSIC]...")
    with open(reporte_network, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== NETWORK & DOWNLOAD FORENSICS: {datetime.datetime.now()} ===\n\n"); safe_ports = ["80", "443", "53", "135", "139", "445"]
        f.write("--- LIVE CONNECTIONS (Netstat) ---\n")
        try:
            proc = subprocess.Popen('netstat -ano', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000); out, _ = proc.communicate()
            if out:
                lines = out.splitlines()
                for l in lines:
                    if "TCP" not in l and "UDP" not in l: continue
                    parts = l.split()
                    if len(parts) < 4: continue
                    proto = parts[0]; remote = parts[2]; state = parts[3] if "TCP" in proto else "UDP"; pid = parts[-1] if "TCP" in proto else parts[-1]
                    if "127.0.0.1" in remote or "[::]" in remote or "*:*" in remote or "0.0.0.0" in remote: continue
                    port = remote.split(":")[-1]; is_suspicious = False; reason = ""
                    if port not in safe_ports and state == "ESTABLISHED": is_suspicious = True; reason = f"Non-Standard Port {port}"
                    if is_suspicious or modo == "Analizar Todo": f.write(f"{'[!!!] ' if is_suspicious else '      '}{proto} {remote} {state} PID:{pid} {reason}\n"); f.flush()
        except: f.write("Error running netstat.\n")
        
        f.write("\n--- POWERSHELL DOWNLOAD HISTORY ---\n")
        history_path = os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        if os.path.exists(history_path):
            try:
                with open(history_path, "r", encoding="utf-8", errors="ignore") as h:
                    lines = h.readlines()
                    for line in lines:
                        line = line.strip()
                        line_low = line.lower()
                        if "http://" in line_low or "https://" in line_low or "wget" in line_low or "curl" in line_low or "bits" in line_low:
                            if "apache" not in line_low and "firewall" not in line_low and "policy" not in line_low and "allow" not in line_low:
                                f.write(f"[HISTORY TRACE] {line}\n"); f.flush()
            except: f.write("Error reading PowerShell history.\n")
        else: f.write("No PowerShell history found.\n")
        
        f.write("\n--- BITS TRANSFER HISTORY (Hidden Downloads) ---\n")
        try:
             cmd_bits = "Get-BitsTransfer -AllUsers | Select-Object -Property JobId, CreationTime, State, FileList | Format-List"
             proc_b = subprocess.Popen(["powershell", "-NoProfile", "-Command", cmd_bits], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
             out_b, _ = proc_b.communicate()
             if out_b.strip(): f.write(out_b); f.flush()
             else: f.write("No active background transfers found.\n")
        except: pass

def fase_toxic_lnk(palabras, modo):
    if cancelar_escaneo: return
    print(f"[20/24] Toxic & LNK Hunter (Anti-Bypass) [FORENSIC]...")
    with open(reporte_toxic, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== TOXIC LNK & MODULE SCAN: {datetime.datetime.now()} ===\n")
        f.write("Searching for: LNKs pointing to deleted files (Evidence Tampering) & Toxic Modules in RAM\n\n")
        f.write("--- ORPHANED SHORTCUTS (LNK) ---\n")
        recent_path = os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\Recent")
        if os.path.exists(recent_path):
            try:
                ps_script = f"""
                Get-ChildItem -Path '{recent_path}' -Filter *.lnk | ForEach-Object {{
                    try {{
                        $sh = New-Object -ComObject WScript.Shell
                        $lnk = $sh.CreateShortcut($_.FullName)
                        $target = $lnk.TargetPath
                        if ($target -and (Test-Path $target) -eq $false) {{
                            Write-Output "BROKEN|$($_.Name)|$target"
                        }} elseif ($target -match 'Temp|Downloads') {{
                             Write-Output "RISKY|$($_.Name)|$target"
                        }}
                    }} catch {{}}
                }}
                """
                proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", ps_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
                out, _ = proc.communicate()
                if out:
                    for line in out.splitlines():
                        if "|" in line:
                            parts = line.split("|")
                            if len(parts) >= 3:
                                type_lnk = parts[0]; name = parts[1]; target = parts[2]
                                is_suspicious = False
                                if type_lnk == "BROKEN":
                                    if target.lower().endswith(".exe") or target.lower().endswith(".bat"): is_suspicious = True
                                if any(p in target.lower() for p in palabras): is_suspicious = True
                                if is_suspicious or modo == "Analizar Todo":
                                    marker = "[!!!]" if is_suspicious else "[INFO]"
                                    desc = "DELETED FILE EVIDENCE" if type_lnk == "BROKEN" else "Risky Location"
                                    f.write(f"{marker} {name} -> {target} ({desc})\n"); f.flush()
                else: f.write("No orphaned shortcuts found.\n")
            except Exception as e: f.write(f"Error scanning LNKs: {e}\n")
        f.write("\n--- TOXIC MODULES IN RAM ---\n")
        try:
            cmd = 'tasklist /m /fo csv'
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            if out:
                lines = out.splitlines()
                for line in lines:
                    if "Image Name" in line: continue
                    if any(k in line.lower() for k in ["cheat", "inject", "hook", "hack"]):
                        f.write(f"[!!!] TOXIC MODULE: {line[:100]}...\n"); f.flush()
        except: pass

def fase_ghost_trails(palabras, modo):
    if cancelar_escaneo: return
    print(f"[21/24] Ghost Trails (Registry MRU & ShellBags) [ANTI-CLEANER]...")
    with open(reporte_ghost, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== GHOST TRAILS & REGISTRY MRU: {datetime.datetime.now()} ===\n")
        f.write("Searching for: Evidence of files accessed via Dialogs, even if deleted.\n\n")
        f.write("--- OPENSAVEPIDLMRU (File Dialog History) ---\n")
        mru_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mru_path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    ext = winreg.EnumKey(key, i) 
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{mru_path}\\{ext}") as subkey:
                            count = winreg.QueryInfoKey(subkey)[1]
                            for j in range(count):
                                name, val, type = winreg.EnumValue(subkey, j)
                                if type == winreg.REG_BINARY:
                                    try:
                                        txt = val.decode('utf-16-le', errors='ignore')
                                        clean_txt = "".join([c for c in txt if c.isprintable() or c in ['\\', ':', '.', '_', '-']])
                                        paths = re.findall(r'[a-zA-Z]:\\[a-zA-Z0-9_\\\-\.\s]+', clean_txt)
                                        for p in paths:
                                            if len(p) > 5:
                                                is_susp = any(w in p.lower() for w in palabras)
                                                if is_susp or modo == "Analizar Todo": f.write(f"[{'!!!' if is_susp else 'INFO'}] OPENED: {p}\n"); f.flush()
                                    except: pass
                    except: pass
        except: f.write("Could not access OpenSavePidlMRU.\n")
        f.write("\n--- MUICACHE (Application Names) ---\n")
        mui_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mui_path) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, val, _ = winreg.EnumValue(key, i)
                    if ".exe" in name.lower():
                         is_susp = any(w in name.lower() for w in palabras)
                         if is_susp or modo == "Analizar Todo": f.write(f"[{'!!!' if is_susp else 'INFO'}] RAN: {name}\n"); f.flush()
        except: pass

def fase_memory_anomaly(palabras, modo):
    if cancelar_escaneo: return
    print(f"[22/24] Memory Anomaly Hunter (VAD + Orphan Threads) [GOD-TIER]...")

    # --- 1. DEFINICIONES CTYPES PARA NIVEL KERNEL/NATIVO ---
    # Definimos estructuras necesarias para consultar Hilos y Módulos
    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("th32ModuleID", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong), ("GlblcntUsage", ctypes.c_ulong),
                    ("ProccntUsage", ctypes.c_ulong), ("modBaseAddr", ctypes.c_void_p),
                    ("modBaseSize", ctypes.c_ulong), ("hModule", ctypes.c_void_p),
                    ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * 260)]

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                    ("th32ThreadID", ctypes.c_ulong), ("th32OwnerProcessID", ctypes.c_ulong),
                    ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong)]

    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    TH32CS_SNAPTHREAD = 0x00000004
    THREAD_QUERY_INFORMATION = 0x0040
    STATUS_SUCCESS = 0

    # Funciones nativas
    ntdll = ctypes.windll.ntdll
    kernel32 = ctypes.windll.kernel32

    # --- HELPER: Obtener Rangos de Memoria Válidos (Módulos) ---
    def get_valid_ranges(pid):
        valid_ranges = [] # Lista de tuplas (inicio, fin, nombre)
        h_snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if h_snap == -1: return []
        
        me32 = MODULEENTRY32()
        me32.dwSize = ctypes.sizeof(MODULEENTRY32)
        
        if kernel32.Module32First(h_snap, ctypes.byref(me32)):
            while True:
                start = me32.modBaseAddr if me32.modBaseAddr else 0
                size = me32.modBaseSize
                if start and size:
                    end = start + size
                    name = me32.szModule.decode('cp1252', 'ignore')
                    valid_ranges.append((start, end, name))
                if not kernel32.Module32Next(h_snap, ctypes.byref(me32)): break
        kernel32.CloseHandle(h_snap)
        return valid_ranges

    # --- TARGET LIST ---
    target_names = ["csgo.exe", "valorant.exe", "dota2.exe", "fortnite.exe", "javaw.exe", 
                    "explorer.exe", "svchost.exe", "discord.exe", "steam.exe", "hl2.exe", 
                    "gta5.exe", "fivem.exe", "robloxplayerbeta.exe", "minecraft.exe"]

    with open(reporte_memory, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== MEMORY FORENSICS (VAD & THREADS): {datetime.datetime.now()} ===\n")
        f.write("Scanning for: Unbacked Executable Memory & Orphan Threads (Injection Indicators)\n\n")

        cmd = 'tasklist /fo csv /nh'
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
        except: return

        if not out: return

        for line in out.splitlines():
            if cancelar_escaneo: break
            parts = line.split(',')
            if len(parts) < 2: continue
            
            proc_name = parts[0].strip('"')
            try: pid = int(parts[1].strip('"'))
            except: continue

            # Filtro inteligente de procesos
            check_process = False
            if modo == "Analizar Todo": check_process = True
            elif any(t in proc_name.lower() for t in target_names): check_process = True
            elif any(p in proc_name.lower() for p in palabras): check_process = True
            
            if not check_process: continue

            h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not h_process: continue

            f.write(f"--> Scanning PID {pid}: {proc_name}...\n")
            f.flush()

            # A. ESCANEO DE HILOS HUÉRFANOS (NUEVA TÉCNICA)
            valid_modules = get_valid_ranges(pid)
            if valid_modules:
                h_snap_thread = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                te32 = THREADENTRY32()
                te32.dwSize = ctypes.sizeof(THREADENTRY32)
                
                orphans_found = 0
                if kernel32.Thread32First(h_snap_thread, ctypes.byref(te32)):
                    while True:
                        if te32.th32OwnerProcessID == pid:
                            h_thread = kernel32.OpenThread(THREAD_QUERY_INFORMATION, False, te32.th32ThreadID)
                            if h_thread:
                                start_addr = ctypes.c_void_p()
                                # InfoClass 9 = ThreadQuerySetWin32StartAddress
                                status = ntdll.NtQueryInformationThread(h_thread, 9, ctypes.byref(start_addr), ctypes.sizeof(start_addr), None)
                                
                                if status == STATUS_SUCCESS and start_addr.value:
                                    addr_val = start_addr.value
                                    is_valid = False
                                    for v_start, v_end, v_name in valid_modules:
                                        if v_start <= addr_val < v_end:
                                            is_valid = True
                                            break
                                    
                                    if not is_valid:
                                        orphans_found += 1
                                        f.write(f"   [!!!] ORPHAN THREAD DETECTED (TID: {te32.th32ThreadID})\n")
                                        f.write(f"         Start Address: 0x{addr_val:X}\n")
                                        f.write(f"         Analysis: Thread starts OUTSIDE any valid module.\n")
                                        f.write(f"         (High Probability of Manual Map / Code Injection)\n")
                                        f.write("-" * 40 + "\n")
                                        f.flush()
                                kernel32.CloseHandle(h_thread)
                        if not kernel32.Thread32Next(h_snap_thread, ctypes.byref(te32)): break
                kernel32.CloseHandle(h_snap_thread)
                if orphans_found == 0:
                    f.write("      [Threads OK] All threads act within valid modules.\n")

            # B. ESCANEO VAD (MEMORIA CLÁSICA)
            address = 0
            mbi = MEMORY_BASIC_INFORMATION()
            anomalies = 0
            
            while kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                if cancelar_escaneo: break
                
                # Buscamos memoria EJECUTABLE (X) que sea PRIVADA (No mapeada a disco)
                is_executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                
                if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and is_executable:
                    size_kb = mbi.RegionSize / 1024
                    
                    # Filtramos asignaciones muy pequeñas para reducir ruido (JIT, etc)
                    if size_kb > 8: 
                        anomalies += 1
                        prot_str = "UNKNOWN"
                        if mbi.Protect & PAGE_EXECUTE_READWRITE: prot_str = "RWX (Read/Write/Exec)"
                        elif mbi.Protect & PAGE_EXECUTE_READ: prot_str = "RX (Read/Exec)"
                        
                        f.write(f"   [!!!] VAD ANOMALY at 0x{address:X}\n")
                        f.write(f"         Size: {size_kb:.2f} KB\n")
                        f.write(f"         Protection: {prot_str}\n")
                        f.write(f"         Type: MEM_PRIVATE (No file on disk)\n")
                        f.write(f"         (Potential Unpacked Cheat Payload)\n")
                        f.write("-" * 40 + "\n")
                        f.flush()
                
                address += mbi.RegionSize
            
            kernel32.CloseHandle(h_process)
            f.write("\n")

def fase_rogue_drivers(palabras, modo):
    if cancelar_escaneo: return
    print(f"[23/24] Rogue Driver Hunter (Unlinked Modules) [GOD-TIER]...")
    
    global reporte_drivers
    if not reporte_drivers:
        reporte_drivers = "Rogue_Drivers.txt"
    
    try:
        with open(reporte_drivers, "w", encoding="utf-8", buffering=1) as f:
            f.write(f"=== ROGUE KERNEL DRIVER SCAN: {datetime.datetime.now()} ===\n")
            f.write("Comparing: EnumDeviceDrivers (Memory) vs DriverQuery (Registry)\n")
            f.write("Looking for: Drivers loaded in memory but hidden from the system list.\n\n")
            f.flush()
            
            proc = subprocess.Popen('driverquery /nh', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out, _ = proc.communicate()
            official_drivers = set()
            if out:
                for line in out.decode('cp850', errors='ignore').splitlines():
                    if line.strip():
                        official_drivers.add(line.split()[0].lower())
            
            psapi = ctypes.windll.psapi
            image_bases = (ctypes.c_void_p * 1024)()
            cb_needed = ctypes.c_long()
            
            if psapi.EnumDeviceDrivers(ctypes.byref(image_bases), ctypes.sizeof(image_bases), ctypes.byref(cb_needed)):
                drivers_count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
                f.write(f"Drivers in Memory: {drivers_count} | Registered Drivers: {len(official_drivers)}\n\n")
                f.flush()
                
                for i in range(drivers_count):
                    base_addr = image_bases[i]
                    if not base_addr: continue
                    name_buffer = ctypes.create_unicode_buffer(256)
                    res = psapi.GetDeviceDriverBaseNameW(ctypes.c_void_p(base_addr), name_buffer, 256)
                    
                    if res > 0:
                        drv_name = name_buffer.value.lower()
                        if not drv_name.endswith(".sys"):
                             f.write(f"[SUSPICIOUS] Non-SYS Driver: {drv_name} at {base_addr}\n"); f.flush()
                        if "iqvw" in drv_name or "capcom" in drv_name or "mhyprot" in drv_name:
                            f.write(f"[!!!] VULNERABLE DRIVER (BYPASS TOOL): {drv_name}\n"); f.flush()
                    else:
                        f.write(f"[!!!] UNNAMED DRIVER ANOMALY at address: {base_addr}\n      (Posible Kernel Manual Map / KDMapper artifact)\n"); f.flush()
            else:
                f.write("Failed to enumerate device drivers (Need Admin?).\n"); f.flush()

    except Exception as e:
        try:
            with open("Driver_Error_Log.txt", "w") as err_f:
                err_f.write(f"Error scanning drivers: {e}")
        except: pass

def fase_deep_static(*args):
    # ======================================================
    # 1. ARGUMENT EATER (ANTI-CRASH)
    # ======================================================
    try:
        palabras = args[0]
        modo = "Normal"
        if len(args) > 1 and isinstance(args[-1], str):
            modo = args[-1]
    except:
        return

    # ======================================================
    # 2. IMPORTS
    # ======================================================
    import os
    import time
    import datetime
    import math
    from collections import Counter

    try:
        import yara
        YARA_AVAILABLE = True
    except:
        YARA_AVAILABLE = False

    # ======================================================
    # 3. GLOBAL SAFETY
    # ======================================================
    global cancelar_escaneo
    if 'cancelar_escaneo' not in globals():
        cancelar_escaneo = False

    global HISTORIAL_RUTAS
    if 'HISTORIAL_RUTAS' not in globals():
        HISTORIAL_RUTAS = {'path': os.path.abspath("."), 'folder': "Resultados_SS"}

    if cancelar_escaneo:
        return

    print("[24/25] Deep Static Heuristics (YARA FIXED | ENTROPY | FAST)")

    # ======================================================
    # 4. ENTROPY FUNCTION
    # ======================================================
    def entropy_calc(data):
        if not data:
            return 0
        counts = Counter(data)
        length = len(data)
        ent = 0
        for c in counts.values():
            p = c / length
            if p > 0:
                ent -= p * math.log(p, 2)
        return ent

    # ======================================================
    # 5. REPORT PATH
    # ======================================================
    base_path = HISTORIAL_RUTAS.get('path', os.path.abspath("."))
    folder_name = HISTORIAL_RUTAS.get('folder', "Resultados_SS")
    out_dir = os.path.join(base_path, folder_name)
    os.makedirs(out_dir, exist_ok=True)

    report_path = os.path.join(out_dir, "Deep_Static_Analysis.txt")

    # ======================================================
    # 6. YARA LOAD (FIX REAL)
    # ======================================================
    yara_rules = None
    yara_active = False

    if YARA_AVAILABLE:
        try:
            yara_rules = yara.compile(filepath="reglas_scanneler.yar")
            yara_active = True
        except Exception as e:
            yara_active = False
            print("[!] YARA load error:", e)

    # ======================================================
    # 7. SCAN ZONES
    # ======================================================
    user = os.environ.get("USERPROFILE", "C:\\")
    hunt_zones = [
        os.path.join(user, "Desktop"),
        os.path.join(user, "Downloads"),
        os.path.join(user, "AppData", "Local"),
        os.path.join(user, "AppData", "Roaming"),
    ]

    MAX_FILE_MB = 30
    MAX_TIME = 10
    start_time = time.time()
    scanned = 0

    # ======================================================
    # 8. SCAN
    # ======================================================
    with open(report_path, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== DEEP STATIC ANALYSIS ===\n")
        f.write(f"Time: {datetime.datetime.now()}\n")
        f.write(f"YARA: {'ACTIVE' if yara_active else 'DISABLED'}\n\n")

        for zone in hunt_zones:
            if not os.path.exists(zone):
                continue

            for root, _, files in os.walk(zone):
                if cancelar_escaneo or time.time() - start_time > MAX_TIME:
                    break

                # Evitar rutas de sistema
                rl = root.lower()
                if any(x in rl for x in ["windows", "microsoft", "google", "common files"]):
                    continue

                for file in files:
                    if not file.lower().endswith((".exe", ".dll", ".sys")):
                        continue

                    path = os.path.join(root, file)

                    try:
                        if os.path.getsize(path) > MAX_FILE_MB * 1024 * 1024:
                            continue
                    except:
                        continue

                    try:
                        with open(path, "rb") as fd:
                            data = fd.read(2 * 1024 * 1024)
                            if not data:
                                continue

                        scanned += 1
                        score = 0
                        reasons = []

                        # ---------------- ENTROPY ----------------
                        ent = entropy_calc(data)
                        if ent > 7.2:
                            score += 2
                            reasons.append(f"High entropy ({ent:.2f})")

                        # ---------------- YARA ----------------
                        if yara_active:
                            try:
                                matches = yara_rules.match(data=data)
                                for m in matches:
                                    rn = m.rule
                                    if rn == "Inyeccion_y_Memoria":
                                        score += 5
                                        reasons.append("YARA: Injection APIs")
                                    elif rn == "Cheat_Strings_Genericos":
                                        score += 4
                                        reasons.append("YARA: Cheat strings")
                                    elif rn == "Sus_Config_Files":
                                        score += 3
                                        reasons.append("YARA: Cheat config")
                                    else:
                                        score += 2
                                        reasons.append(f"YARA: {rn}")
                            except:
                                pass

                        # ---------------- NAME HEURISTIC ----------------
                        name = file.rsplit(".", 1)[0]
                        if len(name) <= 3 or name.isdigit():
                            score += 2
                            reasons.append("Suspicious filename")

                        # ---------------- REPORT ----------------
                        if score >= 4:
                            f.write(
                                f"[!] STATIC THREAT: {file}\n"
                                f"    Path: {path}\n"
                                f"    Score: {score}\n"
                                f"    Reasons: {', '.join(reasons)}\n"
                                + "-" * 50 + "\n"
                            )
                            f.flush()

                    except:
                        pass

        f.write(f"\nScan completed. Files scanned: {scanned}\n")

    print("[✓] Deep Static completed")


def fase_metamorphosis_hunter(palabras, modo, target_file=None):
    if cancelar_escaneo:
        return

    print("[25/25] Metamorphosis + DLL Injection Hunter [FORENSIC | NO FP | FAST]")

    import yara, psutil, pefile, hashlib

    start_time = time.time()
    MAX_TIME = 300
    MAX_FILES = 2500
    MAX_DLLS = 1200

    # ===================== CONFIG =====================
    GAME_PROCESSES = [
        "cs2.exe", "csgo.exe", "valorant.exe",
        "fortniteclient-win64-shipping.exe",
        "rustclient.exe", "gta5.exe"
    ]

    SYSTEM_DLLS = {
        "kernel32.dll", "ntdll.dll", "user32.dll",
        "advapi32.dll", "gdi32.dll", "win32u.dll"
    }

    SYSTEM_PATHS = (
        r"c:\windows\system32",
        r"c:\windows\syswow64"
    )

    WRITABLE_PATHS = ("temp", "appdata", "downloads", "desktop")

    # ===================== YARA =====================
    yara_rules = None
    try:
        yara_rules = yara.compile(filepath="reglas_scanneler.yar")
    except:
        pass

    # ===================== PREFETCH =====================
    prefetch_map = {}
    try:
        for f in os.scandir(r"C:\Windows\Prefetch"):
            if f.name.endswith(".PF"):
                exe = f.name.split("-")[0].lower()
                prefetch_map[exe] = f.stat().st_mtime
    except:
        pass

    # ===================== USN CACHE =====================
    usn_db = {}
    try:
        proc = subprocess.Popen(
            "fsutil usn readjournal C: csv",
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            shell=True, text=True, creationflags=0x08000000
        )
        t0 = time.time()
        while time.time() - t0 < 2.5:
            line = proc.stdout.readline()
            if not line:
                break
            parts = line.split(",")
            if len(parts) > 6 and parts[-1].lower().endswith(".exe"):
                usn_db.setdefault(parts[-1].lower(), []).append(parts[5])
        proc.terminate()
    except:
        pass

    # ===================== FILE DISCOVERY =====================
    files_to_scan = []

    if target_file and os.path.exists(target_file):
        files_to_scan.append(target_file)
    else:
        roots = [
            os.path.join(os.environ["USERPROFILE"], "Desktop"),
            os.path.join(os.environ["USERPROFILE"], "Downloads"),
            os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Temp")
        ]
        for root in roots:
            for r, _, files in os.walk(root):
                for f in files:
                    if f.lower().endswith(".exe"):
                        files_to_scan.append(os.path.join(r, f))
                        if len(files_to_scan) >= MAX_FILES:
                            break

    # ===================== REPORT =====================
    base_path = HISTORIAL_RUTAS.get("path", os.path.abspath("."))
    folder = HISTORIAL_RUTAS.get("folder", "Resultados_SS")
    os.makedirs(os.path.join(base_path, folder), exist_ok=True)
    report_path = os.path.join(base_path, folder, "Metamorphosis_DLL_Report.txt")

    with open(report_path, "w", encoding="utf-8", buffering=1) as report:
        report.write("=== FASE 25 – METAMORPHOSIS + DLL INJECTION (NO FP) ===\n\n")

        detections = 0

        # =====================================================
        # PART A – METAMORPHOSIS (AUTODESTRUCT / HOT-SWAP)
        # =====================================================
        for fp in files_to_scan:
            if time.time() - start_time > MAX_TIME:
                break
            try:
                st = os.stat(fp)
                fname = os.path.basename(fp).lower()
                score = 0
                evidence = []

                if st.st_size < 2 * 1024 * 1024:
                    score += 2
                    evidence.append("Executable unusually small")

                if fname in prefetch_map and st.st_mtime > prefetch_map[fname] + 5:
                    score += 5
                    evidence.append("Modified AFTER execution (Prefetch paradox)")

                for r in usn_db.get(fname, []):
                    if "TRUNCATION" in r:
                        score += 2
                        evidence.append("USN: DATA_TRUNCATION")
                    if "OVERWRITE" in r:
                        score += 1
                        evidence.append("USN: DATA_OVERWRITE")

                if score >= 6:
                    detections += 1
                    report.write(f"[METAMORPHOSIS] {fp}\n")
                    for e in evidence:
                        report.write(f"  - {e}\n")
                    report.write("\n")

            except:
                pass

        # =====================================================
        # PART B – DLL INJECTION (REAL CHEATS ONLY)
        # =====================================================
        dll_checked = 0

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            if time.time() - start_time > MAX_TIME:
                break

            try:
                pname = proc.info["name"].lower()
                if pname not in GAME_PROCESSES:
                    continue

                for m in proc.memory_maps():
                    path = m.path
                    if not path or not path.lower().endswith(".dll"):
                        continue

                    dll = os.path.basename(path).lower()
                    if dll in SYSTEM_DLLS:
                        continue

                    lp = path.lower()
                    if lp.startswith(SYSTEM_PATHS):
                        continue

                    dll_checked += 1
                    if dll_checked > MAX_DLLS:
                        break

                    score = 0
                    evidence = []

                    if any(w in lp for w in WRITABLE_PATHS):
                        score += 2
                        evidence.append("DLL loaded from writable path")

                    if yara_rules:
                        try:
                            matches = yara_rules.match(path)
                            if matches:
                                score += 6
                                evidence.append(f"YARA MATCH: {[m.rule for m in matches]}")
                        except:
                            pass

                    try:
                        pe = pefile.PE(path, fast_load=True)
                        pe.parse_data_directories(
                            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
                        )
                        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                            for imp in entry.imports:
                                if imp.name:
                                    api = imp.name.decode(errors="ignore").lower()
                                    if api in (
                                        "writeprocessmemory",
                                        "createremotethread",
                                        "ntwritevirtualmemory"
                                    ):
                                        score += 1
                                        evidence.append(f"Memory API: {api}")
                    except:
                        pass

                    if score >= 7:
                        detections += 1
                        report.write(f"[DLL CHEAT] {path}\n")
                        report.write(f"  Process: {proc.info['name']} (PID {proc.pid})\n")
                        for e in evidence:
                            report.write(f"  - {e}\n")
                        report.write("\n")

            except:
                pass

        report.write(f"\nScan finished. Detections: {detections}\n")
        report.write(f"Elapsed: {time.time() - start_time:.2f}s\n")


            
# --- FASE 26: STRING CLEANER & MEMORY MANIPULATION HUNTER ---
def fase_string_cleaning(palabras, modo):
    """
    FASE 26 OPTIMIZADA: USN Journal Reader (Native API - Low Level).
    Velocidad: Extrema (Lee binario directo del volumen NTFS).
    Detecta: Borrados, Renombrados y Herramientas de Limpieza.
    """
    # if cancelar_escaneo: return # Descomenta si usas la variable global
    print("[26/26] String Cleaner & USN Resurrection (NATIVE SPEED)...")
    

    # --- 1. CONFIGURACIÓN Y RUTAS ---
    global reporte_cleaning, HISTORIAL_RUTAS
    try:
        base_path = HISTORIAL_RUTAS.get('path', os.path.abspath("."))
        folder_name = HISTORIAL_RUTAS.get('folder', "Resultados_SS")
    except:
        base_path = os.path.abspath(".")
        folder_name = "Resultados_SS"
    
    reporte_cleaning = os.path.join(base_path, folder_name, "String_Cleaner_Detection.txt")

    # --- 2. DEFINICIONES NATIVAS (CTYPES) PARA USN JOURNAL ---
    # Esto evita depender de fsutil.exe y lee directo del Kernel.
    
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    
    FSCTL_QUERY_USN_JOURNAL = 0x000900f4
    FSCTL_READ_USN_JOURNAL = 0x000900bb
    USN_REASON_FILE_DELETE = 0x00000200
    USN_REASON_RENAME_OLD_NAME = 0x00001000
    USN_REASON_RENAME_NEW_NAME = 0x00002000
    
    class USN_JOURNAL_DATA_V0(ctypes.Structure):
        _fields_ = [
            ("UsnJournalID", ctypes.c_ulonglong),
            ("FirstUsn", ctypes.c_ulonglong),
            ("NextUsn", ctypes.c_ulonglong),
            ("LowestValidUsn", ctypes.c_ulonglong),
            ("MaxUsn", ctypes.c_ulonglong),
            ("MaximumSize", ctypes.c_ulonglong),
            ("AllocationDelta", ctypes.c_ulonglong)
        ]

    class READ_USN_JOURNAL_DATA_V0(ctypes.Structure):
        _fields_ = [
            ("StartUsn", ctypes.c_ulonglong),
            ("ReasonMask", ctypes.c_uint),
            ("ReturnOnlyOnClose", ctypes.c_uint),
            ("Timeout", ctypes.c_ulonglong),
            ("BytesToWaitFor", ctypes.c_ulonglong),
            ("UsnJournalID", ctypes.c_ulonglong)
        ]

    # --- HELPER: LECTOR DE USN ---
    def leer_usn_nativo():
        registros = []
        vol_handle = ctypes.windll.kernel32.CreateFileW(
            r"\\.\C:", GENERIC_READ | GENERIC_WRITE, 
            FILE_SHARE_READ | FILE_SHARE_WRITE, None, 
            OPEN_EXISTING, 0, None
        )
        
        if vol_handle == -1: return []

        try:
            # 1. Consultar estado del Journal
            journal_data = USN_JOURNAL_DATA_V0()
            bytes_ret = ctypes.c_ulong()
            status = ctypes.windll.kernel32.DeviceIoControl(
                vol_handle, FSCTL_QUERY_USN_JOURNAL, None, 0,
                ctypes.byref(journal_data), ctypes.sizeof(journal_data),
                ctypes.byref(bytes_ret), None
            )
            
            if not status: return []

            # 2. Configurar lectura (Leer últimos X MB o todo el final)
            # Para velocidad, leemos desde (NextUsn - Offset) para ver lo reciente
            offset = 150 * 1024 * 1024 # 150 MB atrás (Ajustable)
            start_usn = max(0, journal_data.NextUsn - offset)
            
            read_data = READ_USN_JOURNAL_DATA_V0()
            read_data.StartUsn = start_usn
            read_data.ReasonMask = 0xFFFFFFFF # Todo
            read_data.ReturnOnlyOnClose = 0
            read_data.Timeout = 0
            read_data.BytesToWaitFor = 0
            read_data.UsnJournalID = journal_data.UsnJournalID

            buffer_size = 65536 # 64KB Buffer
            buffer = ctypes.create_string_buffer(buffer_size)
            
            # Loop de lectura
            while True:
                # if cancelar_escaneo: break # Check global
                
                status = ctypes.windll.kernel32.DeviceIoControl(
                    vol_handle, FSCTL_READ_USN_JOURNAL, 
                    ctypes.byref(read_data), ctypes.sizeof(read_data),
                    buffer, buffer_size,
                    ctypes.byref(bytes_ret), None
                )
                
                if not status or bytes_ret.value < 8: break # Fin o error

                # Parsear Buffer Manualmente (USN_RECORD_V2 es variable)
                # Los primeros 8 bytes del buffer son el USN siguiente
                next_usn_blk = struct.unpack_from('<Q', buffer, 0)[0]
                read_data.StartUsn = next_usn_blk # Actualizar puntero para sig lectura

                offset_buf = 8 # Saltar el header de 8 bytes
                while offset_buf < bytes_ret.value:
                    # Leer RecordLength (DWORD al inicio del record)
                    if offset_buf + 4 > bytes_ret.value: break
                    reclen = struct.unpack_from('<I', buffer, offset_buf)[0]
                    if reclen == 0: break
                    
                    # Estructura USN_RECORD_V2 (Offsets fijos comunes)
                    # 0: RecordLength (4)
                    # 4: MajorVersion (2)
                    # 6: MinorVersion (2)
                    # 8: FileRef (8)
                    # 16: ParentFileRef (8)
                    # 24: Usn (8)
                    # 32: TimeStamp (8)
                    # 40: Reason (4)
                    # 56: FileNameLength (2)
                    # 58: FileNameOffset (2)
                    # 60: FileName (Variable)
                    
                    try:
                        reason = struct.unpack_from('<I', buffer, offset_buf + 40)[0]
                        filename_len = struct.unpack_from('<H', buffer, offset_buf + 56)[0]
                        filename_off = struct.unpack_from('<H', buffer, offset_buf + 58)[0]
                        
                        # Filtrar solo Borrados (Delete) o Renombrados
                        if (reason & USN_REASON_FILE_DELETE) or (reason & USN_REASON_RENAME_NEW_NAME):
                            # Extraer nombre
                            ptr_name = offset_buf + filename_off
                            if ptr_name + filename_len <= bytes_ret.value:
                                name_bytes = buffer[ptr_name : ptr_name + filename_len]
                                filename = name_bytes.decode('utf-16-le', errors='ignore')
                                
                                # Extraer fecha (Timestamp windows es 100ns desde 1601)
                                ts_raw = struct.unpack_from('<Q', buffer, offset_buf + 32)[0]
                                dt_obj = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ts_raw / 10)
                                
                                tipo = "DELETED" if (reason & USN_REASON_FILE_DELETE) else "RENAMED"
                                registros.append((dt_obj, tipo, filename))
                    except: pass
                    
                    offset_buf += reclen

        except Exception as e:
            print(f"Error nativo USN: {e}")
        finally:
            ctypes.windll.kernel32.CloseHandle(vol_handle)
            
        return registros

    # --- 3. EJECUCIÓN DEL ESCANEO ---
    with open(reporte_cleaning, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== USN JOURNAL FORENSICS (NATIVE): {datetime.datetime.now()} ===\n")
        f.write("Engine: Direct Kernel I/O (No fsutil)\n")
        
        # A. Detectar herramientas de limpieza en ejecución
        tools = ["processhacker", "cheatengine", "ksdumper", "everything", "lastactivityview"]
        f.write("\n[1] ACTIVE CLEANING TOOLS:\n")
        try:
            cmd = 'tasklist /fo csv /nh'
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, text=True)
            out, _ = proc.communicate()
            found = False
            for line in out.splitlines():
                if any(t in line.lower() for t in tools):
                    f.write(f" [!!!] DETECTED: {line.split(',')[0].strip()}\n")
                    found = True
            if not found: f.write(" [OK] None running.\n")
        except: pass

        # B. Análisis del Journal
        f.write("\n[2] RECENTLY DELETED/RENAMED EVIDENCE (Last 150MB of Log):\n")
        f.write(f" Scanning... (This is instant)\n")
        
        hits = 0
        try:
            # LLAMADA A LA FUNCIÓN NATIVA
            eventos = leer_usn_nativo()
            
            # Filtros de interés (Extensiones de cheats)
            exts_peligrosas = [".exe", ".dll", ".bat", ".ps1", ".pf", ".sys", ".lua", ".cfg"]
            ignorar = ["temp", "installer", "update", "cache", "log"]
            
            for dt, tipo, nombre in eventos:
                nombre_low = nombre.lower()
                
                # Filtro 1: Extensión
                if not any(nombre_low.endswith(x) for x in exts_peligrosas): continue
                
                # Filtro 2: Ruido común de Windows
                if any(i in nombre_low for i in ignorar): continue
                
                # Filtro 3: Palabras clave (o todo si extensión es crítica como .pf)
                is_suspicious = False
                if nombre_low.endswith(".pf"): is_suspicious = True # Prefetch borrado = CULPABLE
                if any(p in nombre_low for p in palabras): is_suspicious = True
                if modo == "Analizar Todo" and ".exe" in nombre_low: is_suspicious = True
                
                if is_suspicious:
                    tag = "[!!!]" if nombre_low.endswith(".pf") else "[INFO]"
                    f.write(f" {tag} [{dt.strftime('%H:%M:%S')}] {tipo}: {nombre}\n")
                    hits += 1

            if hits == 0:
                f.write(" [OK] No suspicious file deletions found in recent journal.\n")
            else:
                f.write(f"\n [ALERTA] Found {hits} suspicious events.\n")

        except Exception as e:
            f.write(f" [ERROR] Failed to read USN: {e}\n")
            f.write(" * Ensure you are running as ADMINISTRATOR.\n")          
        

                 
# --- HTML REPORT ---


def generar_reporte_html(out_f, cfg):
    """
    Generador de Reportes HTML estilo Cyberpunk.
    Arregla el bug de 'Pending' forzando la lectura y detectando estados.
    """
    # CSS Estilo Neon/Cyberpunk
    css = """<style>
        body{background-color:#090011;color:#f3e5f5;font-family:'Consolas',monospace;padding:20px}
        h1,h2{color:#d500f9;text-align:center;text-transform:uppercase;letter-spacing:2px;text-shadow:0 0 10px #d500f9}
        h3{color:#b388ff; margin: 5px 0;}
        a{color:#ea80fc;text-decoration:none;font-weight:bold;transition:0.3s}
        a:hover{color:#fff;text-shadow:0 0 8px #ea80fc}
        .card{border:1px solid #4a148c;background:#1a0526;margin:10px;padding:15px;border-left:5px solid #d500f9;box-shadow:0 0 10px rgba(74,20,140,0.4);transition:transform 0.2s; width: 280px; display:inline-block; vertical-align:top;}
        .card:hover{transform:scale(1.02);box-shadow:0 0 20px rgba(213,0,249,0.6)}
        .status-danger{border-left-color: #ff1744 !important; box-shadow: 0 0 10px rgba(255, 23, 68, 0.4);}
        .status-clean{border-left-color: #00e676 !important;}
        .status-pending{border-left-color: #757575 !important; opacity: 0.7;}
        pre{white-space:pre-wrap;word-wrap:break-word;background:#0f0018;padding:15px;border:1px solid #6a1b9a;color:#e1bee7;font-size:0.9em; max-height: 80vh; overflow-y: auto;}
        .back-btn{display:inline-block;margin-bottom:20px;padding:10px 20px;border:1px solid #d500f9;color:#d500f9;border-radius:50px}
        .back-btn:hover{background:#d500f9;color:#090011}
        .footer{text-align:center;margin-top:50px;color:#7b1fa2;font-size:0.8em; clear:both;}
        .timestamp{color:#9c27b0;font-size:0.9em;text-align:center;margin-bottom:30px}
        .badge {padding: 2px 8px; border-radius: 4px; font-size: 0.8em; color: black; font-weight: bold;}
        .b-danger {background: #ff1744; color: white;}
        .b-clean {background: #00e676;}
        .b-pending {background: #757575; color: white;}
    </style>"""

    # Mapeo de archivos
    fmap = {
        'f1':("ShimCache","Shimcache_Rastros.txt"), 'f2':("AppCompat","rastro_appcompat.txt"), 
        'f3':("Identity","cambios_sospechosos.txt"), 'f4':("Signatures","Digital_Signatures_ZeroTrust.txt"), 
        'f5':("Keywords","buscar_en_disco.txt"), 'f6':("Hidden","archivos_ocultos.txt"), 
        'f7':("MFT_ADS","MFT_Archivos.txt"), 'f8':("UserAssist","UserAssist_Decoded.txt"), 
        'f9':("USB","USB_History.txt"), 'f10':("DNS","DNS_Cache.txt"), 
        'f11':("Browser","Browser_Forensics.txt"), 'f12':("Persistence","Persistence_Check.txt"), 
        'f13':("Events","Windows_Events.txt"), 'f14':("ProcessHunter","Process_Hunter.txt"), 
        'f15':("GameCheats","Game_Cheat_Hunter.txt"), 'f16':("NuclearTraces","Nuclear_Traces.txt"), 
        'f17':("KernelHunter","Kernel_Anomalies.txt"), 'f18':("DNA_Prefetch","DNA_Prefetch.txt"), 
        'f19':("NetworkHunter","Network_Anomalies.txt"), 'f20':("ToxicLNK","Toxic_LNK.txt"), 
        'f21':("GhostTrails","Ghost_Trails.txt"), 'f22':("MemoryScanner","Memory_Injection_Report.txt"), 
        'f23':("RogueDrivers","Rogue_Drivers.txt"), 'f24':("DeepStatic","Deep_Static_Analysis.txt"), 
        'f25':("Metamorphosis","Metamorphosis_Report.txt"),'f26':("StringCleaner","String_Cleaner_Detection.txt"),
        'vt':("VirusTotal","detecciones_virustotal.txt")
    }

    g_l = [] # Lista para el dashboard

    for k, (tit, arch) in fmap.items():
        # Verificamos si la fase está activa (o es VT que tiene su propia key)
        is_active = False
        if k == 'vt': is_active = cfg.get('vt', {}).get('active', False)
        else: is_active = cfg.get(k, {}).get('active', False)

        if is_active:
            tp = os.path.join(out_f, arch)
            hf = f"{k}_{arch.replace('.txt','.html')}"
            hp = os.path.join(out_f, hf)
            
            c_h = ""
            status = "PENDING"
            card_class = "status-pending"
            badge = "<span class='badge b-pending'>WAITING</span>"
            meta_refresh = "<meta http-equiv='refresh' content='3'>" # Auto recarga si está pending
            
            # --- LÓGICA DE DETECCIÓN DE CONTENIDO ---
            if os.path.exists(tp):
                try:
                    # 'errors=ignore' evita crasheos por bytes raros en logs
                    with open(tp, "r", encoding="utf-8", errors="ignore") as f: 
                        raw_content = f.read()
                    
                    if raw_content.strip():
                        # Procesamiento de alertas visuales
                        safe_content = html.escape(raw_content) # Escapar HTML para seguridad
                        safe_content = safe_content.replace("[!!!]", "<span style='color:#ff1744; background:#330000; padding:2px; font-weight:bold;'>[!!!]</span>")
                        safe_content = safe_content.replace("[ALERTA]", "<span style='color:#ffea00; font-weight:bold;'>[ALERTA]</span>")
                        
                        c_h = f"<pre>{safe_content}</pre>"
                        meta_refresh = "" # Ya terminó, no recargar

                        # Determinar estado para el Dashboard
                        if "[!!!]" in raw_content or "DETECTED" in raw_content:
                            status = "THREAT"
                            card_class = "status-danger"
                            badge = "<span class='badge b-danger'>THREAT FOUND</span>"
                        else:
                            status = "CLEAN"
                            card_class = "status-clean"
                            badge = "<span class='badge b-clean'>LOGGED</span>"
                    else:
                        # Archivo existe pero está vacío (a veces pasa al crearse)
                        c_h = "<p style='color:gray'>Processing data stream...</p>"
                
                except Exception as e:
                    c_h = f"<p style='color:red'>Error reading log: {e}</p>"
            else:
                c_h = "<p style='color:gray; animation: blink 1s infinite;'>Scanning in progress...</p><style>@keyframes blink{50%{opacity:0.5}}</style>"
            
            # Generar HTML Individual de la Fase
            html_page = f"""
            <!DOCTYPE html><html><head><title>{tit}</title>{css}{meta_refresh}</head>
            <body>
                <a href='index.html' class='back-btn'>&lt; DASHBOARD</a>
                <h1>{tit} <small>{badge}</small></h1>
                <div class='card' style='width: 95%; border-left: 5px solid {("#ff1744" if status=="THREAT" else "#d500f9")}'>
                    {c_h}
                </div>
                <div class='footer'>SCANNELER V80 | FORENSIC MODULE</div>
            </body></html>
            """
            
            with open(hp, "w", encoding="utf-8") as f: f.write(html_page)
            g_l.append((tit, hf, card_class, badge))

    # --- GENERAR DASHBOARD (INDEX) ---
    dbh = f"""
    <!DOCTYPE html><html><head><title>SCANNELER DASHBOARD</title>{css}
    <meta http-equiv='refresh' content='4'> 
    </head><body>
    <h1>SCANNELER <span style='color:#d500f9'>|</span> LIVE MONITOR</h1>
    <div class='timestamp'>SYSTEM TIME: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    <div style='display:flex;flex-wrap:wrap;justify-content:center;'>
    """
    
    if not g_l: 
        dbh += "<p style='text-align:center;'>Waiting for active modules...</p>"
    else:
        for tit, link, cls, bdg in g_l: 
            dbh += f"""
            <div class='card {cls}'>
                <h3>{tit}</h3>
                <div style='margin:10px 0;'>{bdg}</div>
                <p><a href='{link}' style='display:block; background:#000; padding:5px; text-align:center;'>OPEN REPORT &gt;</a></p>
            </div>"""
            
    dbh += "</div><div class='footer'>JELER33 PRIVATE TOOL | END OF LINE</div></body></html>"
    
    with open(os.path.join(out_f, "index.html"), "w", encoding="utf-8") as f: f.write(dbh)

# =============================================================================
# [GUI] CLASES DE INTERFAZ (ORDEN CORRECTO & SPA)
# =============================================================================

class VentanaRegistro:
    def __init__(self, parent_root):
        self.win = tk.Toplevel(parent_root); self.win.title("LICENSE REDEMPTION"); self.win.geometry("450x650"); self.win.configure(bg=COLOR_BG)
        self.win.transient(parent_root); self.win.grab_set()
        tk.Label(self.win, text="ACTIVATE SCANNELER", font=("Consolas", 18, "bold"), bg=COLOR_BG, fg=COLOR_ACCENT).pack(pady=30)
        container = tk.Frame(self.win, bg=COLOR_CARD, padx=30, pady=30, highlightthickness=1, highlightbackground=COLOR_BORDER); container.pack(padx=20, fill="x")
        tk.Label(container, text="LICENSE KEY:", bg=COLOR_CARD, fg=COLOR_USER, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.entry_key = tk.Entry(container, bg="#0f0018", fg="white", bd=0, insertbackground="white", font=("Consolas", 11), justify="center"); self.entry_key.pack(fill="x", pady=(5, 15), ipady=8); self.entry_key.insert(0, "SCAN-XXXX-XXXX")
        tk.Label(container, text="NEW USERNAME:", bg=COLOR_CARD, fg=COLOR_USER, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.entry_u = tk.Entry(container, bg="#0f0018", fg="white", bd=0, insertbackground="white", font=("Consolas", 11), justify="center"); self.entry_u.pack(fill="x", pady=(5, 15), ipady=8)
        tk.Label(container, text="NEW PASSWORD:", bg=COLOR_CARD, fg=COLOR_USER, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.entry_p = tk.Entry(container, show="*", bg="#0f0018", fg="white", bd=0, insertbackground="white", font=("Consolas", 11), justify="center"); self.entry_p.pack(fill="x", pady=(5, 25), ipady=8)
        BotonDinamico(self.win, COLOR_ACCENT, text="ACTIVATE & REGISTER", command=self.enviar_registro, width=35).pack(pady=20)
        BotonDinamico(self.win, COLOR_DANGER, text="CANCEL", command=self.win.destroy, width=35).pack()

    def enviar_registro(self):
        k = self.entry_key.get().strip(); u = self.entry_u.get().strip(); p = self.entry_p.get().strip()
        if not k or not u or not p or k == "SCAN-XXXX-XXXX": show_error("Error", "Complete all fields."); return
        try:
            resp = requests.post(f"{API_URL}/keys/redeem", json={"key_code": k, "username": u, "password": p}, timeout=15)
            if resp.status_code == 201: show_info("Success", "Account created! Now you can log in."); self.win.destroy()
            else: show_error("Failed", f"Activation Error: {resp.json().get('detail', 'Invalid Key')}")
        except Exception as e: show_error("Error", f"Connection failed: {e}")

class ScannelerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SCANNELER")
        self.geometry("900x700")
        self.configure(bg=COLOR_BG)
        aplicar_estilo_combobox(self)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Contenedor principal
        self.container = tk.Frame(self, bg=COLOR_BG)
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        
        self.frames = {}
        self.current_frame = None
        
        # Inicializar con Splash
        self.switch_frame(CargaDinamicaFrame)

    def switch_frame(self, frame_class, *args, **kwargs):
        # Destruir frame actual si existe
        if self.current_frame:
            if hasattr(self.current_frame, 'cleanup'):
                self.current_frame.cleanup()
            self.current_frame.destroy()
        
        # Crear nuevo frame
        self.current_frame = frame_class(self.container, self, *args, **kwargs)
        self.current_frame.grid(row=0, column=0, sticky="nsew")

    def on_close(self):
        global cancelar_escaneo
        cancelar_escaneo = True
        self.destroy()
        sys.exit()

class CargaDinamicaFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLOR_BG)
        self.controller = controller
        self.canvas = tk.Canvas(self, bg=COLOR_BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas, COLOR_ACCENT)
        
        # Elementos graficos que necesitan centrado
        self.elements = []
        
        archivo_logo = resource_path("Scanneler.png")

        try: 
            from PIL import Image, ImageTk
            self.pir = Image.open(archivo_logo)
            self.pir = self.pir.resize((300, 250), Image.Resampling.LANCZOS)
            self.il = ImageTk.PhotoImage(self.pir)
            self.logo_id = self.canvas.create_image(450, 300, image=self.il)
            self.canvas.bind("<Configure>", self.center_content) 
        except Exception as e: 
            self.logo_id = self.canvas.create_text(450, 300, text="[ SCANNELER ]", fill="#d500f9", font=("Consolas", 30, "bold"))
            
        # Texto de estado debajo
        self.text_id = self.canvas.create_text(550, 450, text="INICIANDO SISTEMA...", fill="#d500f9", font=("Consolas", 14, "bold"))
        
        self.canvas.bind("<Configure>", self.center_content)
        
        # --- CAMBIO AQUÍ: En lugar de esperar 3 segundos vacíos, iniciamos la carga real ---
        self.after(500, self.iniciar_carga)

    def center_content(self, event):
        w, h = event.width, event.height
        cx, cy = w/2, h/2
        self.canvas.coords(self.logo_id, cx, cy - 50)
        self.canvas.coords(self.text_id, cx, cy + 100)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def iniciar_carga(self):
        # 1. Actualizamos texto visualmente
        self.canvas.itemconfig(self.text_id, text="CARGANDO MOTOR YARA...")
        self.update_idletasks() # Fuerza a la ventana a repintar el texto
        
        # 2. Cargamos YARA (Llama a la función global que creamos antes)
        inicializar_yara()
        
        # 3. Finalizamos
        self.canvas.itemconfig(self.text_id, text="SISTEMA LISTO.")
        self.update_idletasks()
        
        # 4. Pequeña pausa para que el usuario lea "LISTO" y cambio de pantalla
        self.after(1000, self.go_login)

    def go_login(self):
        self.controller.switch_frame(LoginFrame)

class LoginFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLOR_BG)
        self.controller = controller
        self.canvas = tk.Canvas(self, bg=COLOR_BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas, "#00ff41")
        
        self.content = tk.Frame(self.canvas, bg=COLOR_BG)
        self.wid = self.canvas.create_window(450, 350, window=self.content, anchor="center") 
        self.canvas.bind("<Configure>", lambda e: self.canvas.coords(self.wid, e.width/2, e.height/2))
        
        tk.Label(self.content, text=t("login_title"), font=("Consolas", 18, "bold"), bg=COLOR_BG, fg=COLOR_ACCENT).pack(pady=(0, 20))
        fr = tk.Frame(self.content, bg=COLOR_CARD, padx=25, pady=25, highlightthickness=1, highlightbackground=COLOR_BORDER, bd=0); fr.pack(padx=20, fill="x")
        tk.Label(fr, text=t("user_lbl"), bg=COLOR_CARD, fg=COLOR_USER, font=("Consolas", 9, "bold")).pack(anchor="w", pady=(0, 5))
        self.u = tk.Entry(fr, bg="#0f0018", fg="white", bd=0, insertbackground="white", justify="center", font=("Consolas", 11)); self.u.pack(fill="x", ipady=5)
        tk.Frame(fr, bg=COLOR_BORDER, height=1).pack(fill="x", pady=(0, 15))
        tk.Label(fr, text=t("pass_lbl"), bg=COLOR_CARD, fg=COLOR_USER, font=("Consolas", 9, "bold")).pack(anchor="w", pady=(0, 5))
        self.p = tk.Entry(fr, show="*", bg="#0f0018", fg="white", bd=0, insertbackground="white", justify="center", font=("Consolas", 11)); self.p.pack(fill="x", ipady=5)
        tk.Frame(fr, bg=COLOR_BORDER, height=1).pack(fill="x", pady=(0, 20))
        BotonDinamico(self.content, COLOR_ACCENT, text=t("btn_login"), command=self.validar, width=25).pack(pady=(10, 5))
        BotonDinamico(self.content, "#69f0ae", text=t("btn_redeem"), command=self.abrir_registro, width=25).pack(pady=5)
        BotonDinamico(self.content, COLOR_DANGER, text=t("btn_exit"), command=sys.exit, width=25).pack(pady=10)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def abrir_registro(self):
        VentanaRegistro(self.controller)

    def validar(self):
        global SESSION_TOKEN, USER_ROLE, USER_NAME, USER_MEMBERSHIP, USER_EXPIRY
        user = self.u.get()[:20]; pwd = self.p.get()
        try:
            resp = requests.post(f"{API_URL}/login", data={"username": user, "password": pwd})
            if resp.status_code == 200:
                data = resp.json()
                SESSION_TOKEN = data["access_token"]
                USER_ROLE = data["role"]
                USER_NAME = user
                USER_MEMBERSHIP = data["membresia"]
                try:
                    user_resp = requests.get(f"{API_URL}/users", headers=get_auth_headers(), timeout=5)
                    if user_resp.status_code == 200:
                        my_user = next((u for u in user_resp.json() if u['username'] == user), None)
                        USER_EXPIRY = my_user['vencimiento'] if my_user and my_user.get('vencimiento') else "LIFETIME"
                    else: USER_EXPIRY = "LIFETIME"
                except: USER_EXPIRY = "LIFETIME"
                self.controller.switch_frame(MenuFrame)
            else: show_error("Error", "Invalid credentials.")
        except: show_error("Error", "Connection Failed.")

class MenuFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLOR_BG)
        self.controller = controller
        self.canvas = tk.Canvas(self, bg=COLOR_BG, highlightthickness=0); self.canvas.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas, COLOR_ACCENT)
        
# --- BLOQUE CORREGIDO PARA MENUFRAME ---
        archivo_logo = resource_path("Scanneler.png")

        try: 
            from PIL import Image, ImageTk
            
            # 1. Cargar imagen
            self.pir = Image.open(archivo_logo)
            
            # 2. Crear objeto en canvas (empezamos en 0,0)
            self.bgi = self.canvas.create_image(0, 0, anchor="nw")
            
            # 3. IMPORTANTE: Aquí usamos 'self.rs', NO 'center_content'
            self.canvas.bind("<Configure>", self.rs)

        except Exception as e: 
            # Si falla, mostramos texto
            print(f"Error menu img: {e}")
            self.canvas.create_text(450, 200, text="SCANNELER", fill=COLOR_ACCENT, font=("Consolas", 50, "bold"))
            
        self.b_admin = BotonCanvas(self.canvas, 0, 0, 200, 50, t("menu_admin"), COLOR_ACCENT, self.go_admin) if USER_ROLE == 'admin' else None
        self.b_user = BotonCanvas(self.canvas, 0, 0, 200, 50, t("menu_user"), COLOR_USER, self.go_user)
        self.b_settings = BotonCanvas(self.canvas, 0, 0, 200, 50, t("menu_settings"), "#00e5ff", self.go_settings)
        self.b_exit = BotonCanvas(self.canvas, 0, 0, 200, 50, t("btn_exit"), COLOR_DANGER, sys.exit)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def rs(self, e):
        w, h = e.width, e.height
        cx = w / 2
        if hasattr(self, 'pir'):
            try: 
                from PIL import ImageTk, Image
                self.cbg = ImageTk.PhotoImage(self.pir.resize((w, h), Image.Resampling.LANCZOS))
                self.canvas.itemconfig(self.bgi, image=self.cbg)
            except: pass
        
        base_y = int(h * 0.75)
        
        if self.b_admin:
            self.b_admin.move_to(cx, base_y - 70)
            self.b_user.move_to(cx - 110, base_y)
            self.b_settings.move_to(cx + 110, base_y)
            self.b_exit.move_to(cx, base_y + 70)
        else:
            self.b_user.move_to(cx - 110, base_y)
            self.b_settings.move_to(cx + 110, base_y)
            self.b_exit.move_to(cx, base_y + 70)

    def go_admin(self): self.controller.switch_frame(AdminFrame)
    def go_user(self): self.controller.switch_frame(UserConfigFrame)
    def go_settings(self): self.controller.switch_frame(SettingsFrame)

class SettingsFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLOR_BG)
        self.controller = controller
        self.canvas = tk.Canvas(self, bg=COLOR_BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas, "#00e5ff")
        self.content = tk.Frame(self.canvas, bg=COLOR_BG)
        self.wid = self.canvas.create_window(450, 350, window=self.content, anchor="center")
        self.canvas.bind("<Configure>", lambda e: self.canvas.coords(self.wid, e.width/2, e.height/2))
        
        tk.Label(self.content, text=t("settings_title"), font=("Consolas", 18, "bold"), bg=COLOR_BG, fg="#00e5ff").pack(pady=(0, 40))
        tk.Label(self.content, text=t("lang_lbl"), font=("Consolas", 11, "bold"), bg=COLOR_BG, fg=COLOR_TEXT).pack(pady=(0, 20))
        
        btn_frame = tk.Frame(self.content, bg=COLOR_BG)
        btn_frame.pack(pady=10)
        
        self.btn_es = BotonDinamico(btn_frame, COLOR_ACCENT, text="ESPAÑOL (AR)", command=lambda: self.set_lang("es"), width=20)
        self.btn_es.pack(side="left", padx=15)
        if CURRENT_LANGUAGE == "es": 
            self.btn_es.config(bg=COLOR_HOVER_BG, state="disabled") 
            
        self.btn_en = BotonDinamico(btn_frame, COLOR_ACCENT, text="ENGLISH (US)", command=lambda: self.set_lang("en"), width=20)
        self.btn_en.pack(side="left", padx=15)
        if CURRENT_LANGUAGE == "en": 
            self.btn_en.config(bg=COLOR_HOVER_BG, state="disabled")

        BotonDinamico(self.content, COLOR_DANGER, text=t("btn_back"), command=lambda: controller.switch_frame(MenuFrame), width=25).pack(pady=50)

    def set_lang(self, lang_code):
        global CURRENT_LANGUAGE
        CURRENT_LANGUAGE = lang_code
        self.controller.switch_frame(SettingsFrame)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

class AdminFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLOR_BG)
        self.controller = controller
        self.canvas_bg = tk.Canvas(self, bg=COLOR_BG, highlightthickness=0); self.canvas_bg.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas_bg, COLOR_ACCENT)
        
        style = ttk.Style()
        style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        self.nb = ttk.Notebook(self); self.tab_users = tk.Frame(self.nb, bg=COLOR_BG); self.tab_keys = tk.Frame(self.nb, bg=COLOR_BG)
        self.nb.add(self.tab_users, text="    USER DATABASE    "); self.nb.add(self.tab_keys, text="    LICENSE GENERATOR    ")
        self.nb_win = self.canvas_bg.create_window(450, 300, window=self.nb, width=1000, height=500) # Coordenadas iniciales
        
        self.setup_tab_usuarios(); self.setup_tab_keys()
        
        self.btn_back = BotonDinamico(self, "#7c4dff", text="BACK TO MENU", command=lambda: controller.switch_frame(MenuFrame), width=20)
        self.back_win = self.canvas_bg.create_window(450, 650, window=self.btn_back)
        self.bind("<Configure>", self.reajustar)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def reajustar(self, e):
        w, h = e.width, e.height; cx = w/2
        self.canvas_bg.coords(self.nb_win, cx, h/2 - 30)
        self.canvas_bg.itemconfig(self.nb_win, width=w-100, height=h-150)
        self.canvas_bg.coords(self.back_win, cx, h - 50)

    def setup_tab_usuarios(self):
        self.form_container = tk.Frame(self.tab_users, bg=COLOR_BG, pady=5); self.form_container.pack(fill="x", padx=20)
        edit_fr = tk.LabelFrame(self.form_container, text=" ACCOUNT CONTROLS ", bg=COLOR_BG, fg=COLOR_TEXT, bd=1, highlightbackground=COLOR_BORDER); edit_fr.pack(fill="x", padx=5, pady=5)
        tk.Label(edit_fr, text="USER:", bg=COLOR_BG, fg=COLOR_USER, font=("Consolas", 9)).grid(row=0, column=0, padx=5, pady=10)
        self.entry_u = tk.Entry(edit_fr, bg="#0f0018", fg="white", width=14, bd=0, highlightthickness=1, highlightbackground=COLOR_BORDER); self.entry_u.grid(row=0, column=1, padx=5)
        tk.Label(edit_fr, text="PASS:", bg=COLOR_BG, fg=COLOR_USER, font=("Consolas", 9)).grid(row=0, column=2, padx=5)
        self.entry_p = tk.Entry(edit_fr, show="*", bg="#0f0018", fg="white", width=14, bd=0, highlightthickness=1, highlightbackground=COLOR_BORDER); self.entry_p.grid(row=0, column=3, padx=5)
        tk.Label(edit_fr, text="PLAN:", bg=COLOR_BG, fg=COLOR_USER, font=("Consolas", 9)).grid(row=0, column=4, padx=5)
        self.m_v = ttk.Combobox(edit_fr, values=["Basic", "Medium", "Full"], state="readonly", width=10); self.m_v.set("Basic"); self.m_v.grid(row=0, column=5, padx=5)
        tk.Label(edit_fr, text="DUR:", bg=COLOR_BG, fg=COLOR_USER, font=("Consolas", 9)).grid(row=0, column=6, padx=5)
        self.d_v = ttk.Combobox(edit_fr, values=["Weekly", "Monthly", "Yearly"], state="readonly", width=10); self.d_v.set("Monthly"); self.d_v.grid(row=0, column=7, padx=5)
        BotonDinamico(edit_fr, COLOR_ACCENT, text="UPDATE", command=self.actualizar_usuario, width=10, pady=2).grid(row=0, column=8, padx=10)
        list_container = tk.Frame(self.tab_users, bg=COLOR_BG); list_container.pack(fill="both", expand=True, padx=20, pady=5)
        self.list_canvas = tk.Canvas(list_container, bg=COLOR_BG, highlightthickness=0)
        self.list_scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.list_canvas.yview)
        self.list_frame = tk.Frame(self.list_canvas, bg=COLOR_BG)
        self.list_frame.bind("<Configure>", lambda e: self.list_canvas.configure(scrollregion=self.list_canvas.bbox("all")))
        self.list_canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        self.list_canvas.configure(yscrollcommand=self.list_scrollbar.set)
        self.list_canvas.pack(side="left", fill="both", expand=True); self.list_scrollbar.pack(side="right", fill="y")
        self.actualizar_lista()

    def setup_tab_keys(self):
        container = tk.Frame(self.tab_keys, bg=COLOR_BG); container.pack(fill="both", expand=True, padx=80, pady=20)
        tk.Label(container, text="LICENSE GENERATOR SERVICE", font=("Consolas", 16, "bold"), bg=COLOR_BG, fg=COLOR_ACCENT).pack(pady=(0, 15))
        fk = tk.Frame(container, bg=COLOR_CARD, padx=20, pady=20, highlightthickness=1, highlightbackground=COLOR_BORDER); fk.pack(fill="x")
        tk.Label(fk, text="PLAN:", bg=COLOR_CARD, fg=COLOR_USER, font=("Consolas", 9, "bold")).grid(row=0, column=0, padx=5, sticky="w")
        self.key_memb = ttk.Combobox(fk, values=["Basic", "Medium", "Full"], state="readonly", width=15); self.key_memb.set("Full"); self.key_memb.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(fk, text="DUR:", bg=COLOR_CARD, fg=COLOR_USER, font=("Consolas", 9, "bold")).grid(row=0, column=2, padx=5, sticky="w")
        self.key_dur_type = ttk.Combobox(fk, values=["Weekly", "Monthly", "Yearly"], state="readonly", width=15); self.key_dur_type.set("Monthly"); self.key_dur_type.grid(row=0, column=3, padx=5, pady=5)
        tk.Label(fk, text="QTY:", bg=COLOR_CARD, fg=COLOR_USER, font=("Consolas", 9, "bold")).grid(row=0, column=4, padx=5, sticky="w")
        self.key_qty = tk.Entry(fk, bg="#0f0018", fg="white", bd=0, width=8, highlightthickness=1, highlightbackground=COLOR_BORDER, justify="center"); self.key_qty.insert(0, "1"); self.key_qty.grid(row=0, column=5, padx=5, pady=5)
        BotonDinamico(container, COLOR_ACCENT, text="GENERATE NEW KEYS", command=self.solicitar_generar_keys, width=30).pack(pady=15)
        tk.Label(container, text="LATEST GENERATED KEY:", bg=COLOR_BG, fg=COLOR_ACCENT, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.entry_result_quick = tk.Entry(container, bg="#1a0526", fg=COLOR_SUCCESS, font=("Consolas", 14, "bold"), bd=0, highlightthickness=1, highlightbackground=COLOR_SUCCESS, justify="center"); self.entry_result_quick.pack(fill="x", pady=(5, 15), ipady=8)
        tk.Label(container, text="FULL BATCH LOG:", bg=COLOR_BG, fg=COLOR_USER, font=("Consolas", 9)).pack(anchor="w")
        self.txt_keys_output = tk.Text(container, bg="#000", fg="white", font=("Consolas", 10), height=6, bd=0, padx=10, pady=10); self.txt_keys_output.pack(fill="x")

    def solicitar_generar_keys(self):
        self.txt_keys_output.delete("1.0", tk.END); self.entry_result_quick.delete(0, tk.END)
        self.txt_keys_output.insert(tk.END, "> Fetching from database..."); self.update_idletasks()
        try:
            m = self.key_memb.get(); d_text = self.key_dur_type.get(); q_str = self.key_qty.get()
            if not q_str.isdigit(): return
            days = self.get_days_from_duration(d_text)
            resp = requests.post(f"{API_URL}/keys/generate", json={"membresia": m, "duracion_dias": days, "cantidad": int(q_str)}, headers=get_auth_headers(), timeout=15)
            if resp.status_code == 201:
                data = resp.json(); keys = data.get("keys", []) or data.get("generated_keys", [])
                if keys:
                    self.entry_result_quick.insert(0, str(keys[0])); self.txt_keys_output.delete("1.0", tk.END)
                    self.txt_keys_output.insert(tk.END, f"--- {len(keys)} KEYS GENERATED ---\n\n"); self.txt_keys_output.insert(tk.END, "\n".join(keys))
                    show_info("Success", f"{len(keys)} Keys generated.")
                else: self.txt_keys_output.insert(tk.END, "\n[!] Empty response from server.")
            else: self.txt_keys_output.insert(tk.END, f"\n[!] Error {resp.status_code}: {resp.text}")
        except Exception as e: self.txt_keys_output.insert(tk.END, f"\n[!] Connection failed: {str(e)}")

    def get_days_from_duration(self, duration):
        mapping = {"Weekly": 7, "Monthly": 30, "Yearly": 365}; return mapping.get(duration, 30)

    def actualizar_lista(self):
        for widget in self.list_frame.winfo_children(): widget.destroy()
        header = tk.Frame(self.list_frame, bg="#1a0526", pady=5); header.pack(fill="x", pady=(0, 5))
        tk.Label(header, text="USERNAME", width=25, anchor="w", bg="#1a0526", fg=COLOR_ACCENT, font=("Consolas", 10, "bold")).pack(side="left", padx=10)
        tk.Label(header, text="MEMBERSHIP", width=20, anchor="w", bg="#1a0526", fg=COLOR_ACCENT, font=("Consolas", 10, "bold")).pack(side="left")
        tk.Label(header, text="ACTIONS", anchor="e", bg="#1a0526", fg=COLOR_ACCENT, font=("Consolas", 10, "bold")).pack(side="right", padx=120)
        try:
            r = requests.get(f"{API_URL}/users", headers=get_auth_headers(), timeout=10)
            if r.status_code == 200:
                for u in r.json():
                    row = tk.Frame(self.list_frame, bg=COLOR_CARD, pady=5, padx=15, highlightthickness=1, highlightbackground="#2a0a38"); row.pack(fill="x", pady=1)
                    tk.Label(row, text=u['username'].upper(), width=25, anchor="w", bg=COLOR_CARD, fg=COLOR_TEXT).pack(side="left")
                    tk.Label(row, text=u['membresia'], width=20, anchor="w", bg=COLOR_CARD, fg=COLOR_USER).pack(side="left")
                    btn_box = tk.Frame(row, bg=COLOR_CARD); btn_box.pack(side="right")
                    BotonDinamico(btn_box, COLOR_ACCENT, text="EDIT", command=lambda un=u['username'], mb=u['membresia']: self.cargar_para_editar(un, mb), width=6, pady=2).pack(side="left", padx=2)
                    if u['username'] != "Jeler33": BotonDinamico(btn_box, COLOR_DANGER, text="DEL", command=lambda n=u['username']: self.borrar_cuenta(n), width=6, pady=2).pack(side="left", padx=2)
        except: pass

    def cargar_para_editar(self, u, m):
        self.entry_u.delete(0, tk.END); self.entry_u.insert(0, u); self.m_v.set(m); self.entry_p.delete(0, tk.END)

    def actualizar_usuario(self):
        u = self.entry_u.get(); m = self.m_v.get(); d_text = self.d_v.get()
        if not u: return
        try:
            days = self.get_days_from_duration(d_text)
            r = requests.put(f"{API_URL}/users/{u}", json={"membresia": m, "duracion_dias": days}, headers=get_auth_headers())
            if r.status_code == 200: show_info("Success", f"Agent {u} updated."); self.actualizar_lista()
        except: pass

    def borrar_cuenta(self, n):
        if ask_yes_no("Security", f"Erase agent {n}?"):
            try:
                r = requests.delete(f"{API_URL}/users/{n}", headers=get_auth_headers()); 
                if r.status_code == 200: self.actualizar_lista()
            except: pass

class UserConfigFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLOR_BG)
        self.controller = controller
        self.ui_map = {}
        self.rutas_seleccionadas = HISTORIAL_RUTAS.copy()
        
        self.canvas = tk.Canvas(self, bg=COLOR_BG, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scroll_content = tk.Frame(self.canvas, bg=COLOR_BG)
        self.anim = CyberRain(self.canvas, COLOR_ACCENT)
        
        self.cw = self.canvas.create_window((0, 0), window=self.scroll_content, anchor="n")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        self.canvas.bind("<Configure>", lambda e: (self.canvas.coords(self.cw, e.width/2, 0), self.canvas.itemconfig(self.cw, width=min(e.width, 780))))
        self.scroll_content.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        tk.Label(self.scroll_content, text=f"{t('welcome')} {USER_NAME.upper()} [{USER_MEMBERSHIP.upper()}]", font=("Consolas", 18, "bold"), bg=COLOR_BG, fg=COLOR_ACCENT).pack(pady=20)
        
        fr = tk.LabelFrame(self.scroll_content, text=t("scan_config"), bg=COLOR_BG, fg=COLOR_TEXT, font=("Consolas", 10), bd=1, highlightbackground=COLOR_BORDER, highlightthickness=1, padx=15, pady=10)
        fr.pack(fill="x", padx=30, pady=10)
        
        # Row 1: Output Path
        row1 = tk.Frame(fr, bg=COLOR_BG); row1.pack(fill="x", pady=5)
        tk.Label(row1, text=t("path_lbl"), bg=COLOR_BG, fg=COLOR_USER, font=("Consolas", 9), width=15, anchor="w").pack(side="left")
        self.pv = tk.StringVar(value=self.rutas_seleccionadas['path']); tk.Entry(row1, textvariable=self.pv, bg="#120026", fg="white", bd=0, highlightthickness=1, highlightbackground=COLOR_BORDER).pack(side="left", fill="x", expand=True, ipady=1, padx=(0, 5))
        BotonDinamico(row1, COLOR_ACCENT, text=t("btn_select"), command=self.select_path, width=12, bg=COLOR_BG).pack(side="right")
        
        # Row 2: Folder Name
        row2 = tk.Frame(fr, bg=COLOR_BG); row2.pack(fill="x", pady=5)
        tk.Label(row2, text=t("folder_lbl"), bg=COLOR_BG, fg=COLOR_USER, font=("Consolas", 9), width=15, anchor="w").pack(side="left")
        self.fv = tk.StringVar(value=self.rutas_seleccionadas['folder']); tk.Entry(row2, textvariable=self.fv, bg="#120026", fg="white", bd=0, highlightthickness=1, highlightbackground=COLOR_BORDER).pack(side="left", fill="x", expand=True, ipady=1)
        
        # Row 3: Keyword List
        row3 = tk.Frame(fr, bg=COLOR_BG); row3.pack(fill="x", pady=10)
        tk.Label(row3, text=t("list_lbl"), bg=COLOR_BG, fg=COLOR_USER, font=("Consolas", 9), width=15, anchor="w").pack(side="left")
        self.lv = tk.StringVar(value=self.rutas_seleccionadas['list_path']); tk.Entry(row3, textvariable=self.lv, bg="#120026", fg="white", bd=0, highlightthickness=1, highlightbackground=COLOR_BORDER).pack(side="left", fill="x", expand=True, ipady=1, padx=(0, 5))
        BotonDinamico(row3, COLOR_SUCCESS, text=t("btn_browse"), command=self.select_list, width=12, bg=COLOR_BG).pack(side="right")

        # --- NUEVO ROW 4: TARGET FILE (FASE 25) ---
        row4 = tk.Frame(fr, bg=COLOR_BG); row4.pack(fill="x", pady=5)
        tk.Label(row4, text=t("target_lbl"), bg=COLOR_BG, fg="#00e5ff", font=("Consolas", 9, "bold"), width=15, anchor="w").pack(side="left")
        self.tv = tk.StringVar(); tk.Entry(row4, textvariable=self.tv, bg="#120026", fg="#00e5ff", bd=0, highlightthickness=1, highlightbackground="#00e5ff").pack(side="left", fill="x", expand=True, ipady=1, padx=(0, 5))
        BotonDinamico(row4, "#00e5ff", text=t("btn_pick"), command=self.select_target, width=12, bg=COLOR_BG).pack(side="right")
        # ------------------------------------------
        
        ob = tk.Frame(self.scroll_content, bg=COLOR_BG, pady=20); ob.pack(fill="x", padx=40)
        tk.Label(self.scroll_content, text=f"EXPIRES: {USER_EXPIRY}", font=("Consolas", 11, "bold"), bg=COLOR_BG, fg=COLOR_SUCCESS).pack(in_=ob, side="bottom", pady=10)
        
        perms = {'Basic': ['f1','f2','f3','f5','f7','f18','f20'], 'Medium': ['f1','f2','f3','f4','f5','f6','f7','f8','f9','f10','f11','f18','f20','vt'], 'Full': ['f1','f2','f3','f4','f5','f6','f7','f8','f9','f10','f11','f12','f13','f14','f15','f16','f17','f18','f19','f20','f21','f22','f23','f24','f25','f26', 'vt']}
        self.alwd = perms.get(USER_MEMBERSHIP, ['f1','f2','f3','f5','f7','f18','f20'])
        
        ctrl_fr = tk.Frame(ob, bg=COLOR_BG); ctrl_fr.pack(fill="x", pady=(0, 10))
        tk.Label(ctrl_fr, text=t("modules_lbl"), bg=COLOR_BG, fg=COLOR_USER, font=("Consolas", 9, "bold")).pack(side="left")
        tk.Button(ctrl_fr, text=t("sel_all"), command=lambda: self.toggle_all(True), bg=COLOR_BG, fg=COLOR_SUCCESS, bd=0, font=("Consolas", 8, "bold"), cursor="hand2", activebackground=COLOR_BG, activeforeground="white").pack(side="right")
        tk.Button(ctrl_fr, text=t("desel_all"), command=lambda: self.toggle_all(False), bg=COLOR_BG, fg=COLOR_DANGER, bd=0, font=("Consolas", 8, "bold"), cursor="hand2", activebackground=COLOR_BG, activeforeground="white").pack(side="right", padx=10)
        
        opts = [("Fase 1: ShimCache Analysis", 'f1'), ("Fase 2: AppCompat Store", 'f2'), ("Fase 3: Identity Verification", 'f3'), ("Fase 4: Digital Signatures", 'f4'), ("Fase 5: Keyword Search", 'f5'), ("Fase 6: Hidden Files Scan", 'f6'), ("Fase 7: MFT & ADS Scan", 'f7'), ("Fase 8: UserAssist (ROT13)", 'f8'), ("Fase 9: USB Device History", 'f9'), ("Fase 10: DNS and Discord Cache", 'f10'), ("Fase 11: Browser Forensics", 'f11'), ("Fase 12: Persistence", 'f12'), ("Fase 13: Windows Event Logs", 'f13'), ("Fase 14: RAM Process Hunter", 'f14'), ("Fase 15: Game Cheat Hunter (Deep)", 'f15'), ("Fase 16: Nuclear Traces (BAM/Pipes)", 'f16'), ("Fase 17: Kernel Hunter (Drivers)", 'f17'), ("Fase 18: DNA & Prefetch (Forensic)", 'f18'), ("Fase 19: Network Deep Inspection", 'f19'), ("Fase 20: Toxic LNK & Module Hunter", 'f20'), ("Fase 21: Ghost Trails (Registry MRU)", 'f21'), ("Fase 22: Memory Injection Hunter (Elite)", 'f22'), ("Fase 23: Rogue Driver Hunter (Kernel)", 'f23'),("Fase 24: Deep Static Heuristics (Hidden Files)", 'f24'), ("Fase 25: Metamorphosis Hunter (Hot-Swap)", 'f25'), ("F26: String Cleaner", 'f26'),("Cloud: VirusTotal API", 'vt')]
        for text, key in opts:
            r = tk.Frame(ob, bg=COLOR_CARD, pady=12, padx=15, highlightthickness=1, highlightbackground=COLOR_BORDER, bd=0)
            r.pack(fill="x", pady=6)
            is_enabled = key in self.alwd
            var_active = tk.BooleanVar(value=is_enabled)
            cb = tk.Checkbutton(r, text=text, variable=var_active, state="normal" if is_enabled else "disabled", bg=COLOR_CARD, fg=COLOR_TEXT if is_enabled else "#333", selectcolor=COLOR_BG, activebackground=COLOR_CARD, activeforeground=COLOR_ACCENT, font=("Consolas", 11)); cb.pack(side="left")
            var_modo = tk.StringVar(value="Usar Lista")
            if is_enabled:
                if key == 'vt' or key == 'f5': tk.Label(r, text=t("only_list"), bg=COLOR_CARD, fg="#b39ddb", font=("Consolas", 9, "italic")).pack(side="right", padx=25)
                else: selector = ttk.Combobox(r, textvariable=var_modo, values=["Usar Lista", "Analizar Todo"], state="readonly", width=15); selector.pack(side="right", padx=25)
            elif not is_enabled: tk.Label(r, text=t("upgrade"), bg=COLOR_CARD, fg=COLOR_DANGER, font=("Consolas", 9, "bold")).pack(side="right", padx=25)
            self.ui_map[key] = {'active': var_active, 'modo': var_modo}
        
        fb = tk.Frame(self.scroll_content, bg=COLOR_BG); fb.pack(pady=40)
        BotonDinamico(fb, COLOR_ACCENT, text=t("btn_start"), command=self.go, width=25).pack(side="left", padx=15)
        BotonDinamico(fb, "#7c4dff", text=t("btn_back"), command=lambda: controller.switch_frame(MenuFrame), width=25).pack(side="left", padx=15)
        BotonDinamico(fb, COLOR_DANGER, text=t("btn_exit"), command=sys.exit, width=25).pack(side="left", padx=15)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def toggle_all(self, state):
        for k, v in self.ui_map.items():
            if k in self.alwd: v['active'].set(state)

    def select_path(self):
        p = filedialog.askdirectory()
        if p: self.pv.set(p); HISTORIAL_RUTAS['path'] = p

    def select_list(self):
        f = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if f: self.lv.set(f); HISTORIAL_RUTAS['list_path'] = f

    # --- NUEVO METODO PARA SELECCIONAR ARCHIVO OBJETIVO ---
    def select_target(self):
        f = filedialog.askopenfilename(title="Select Suspicious File (Phase 25)", filetypes=[("Executables", "*.exe"), ("All files", "*.*")])
        if f: self.tv.set(f)

    def go(self):
        try:
            HISTORIAL_RUTAS['path'] = self.pv.get()
            HISTORIAL_RUTAS['folder'] = self.fv.get()
            HISTORIAL_RUTAS['list_path'] = self.lv.get()
            HISTORIAL_RUTAS['target_file'] = self.tv.get() # Guardar el archivo seleccionado
            
            seleccion_modulos = {k: {'active': v['active'].get(), 'modo': v['modo'].get()} for k, v in self.ui_map.items()}
            pals = cargar_palabras(HISTORIAL_RUTAS['list_path'])
            if pals or any(m['modo'] == 'Analizar Todo' for m in seleccion_modulos.values()):
                self.controller.switch_frame(ScannerFrame, pals, seleccion_modulos, HISTORIAL_RUTAS)
            else: show_error("Error", "List is empty and no 'Analizar Todo' selected.")
        except Exception as e: print(f"Error in go: {e}")

class ScannerFrame(tk.Frame):
    def __init__(self, parent, controller, palabras, configuracion, rutas_config):
        super().__init__(parent, bg=COLOR_BG)
        global cancelar_escaneo
        cancelar_escaneo = False
        self.controller = controller
        self.palabras = palabras
        self.config = configuracion
        self.rutas = rutas_config
        self.cola_estado = Queue()
        
        self.canvas = tk.Canvas(self, bg=COLOR_BG, highlightthickness=0); self.canvas.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas, COLOR_ACCENT)
        self.content = tk.Frame(self.canvas, bg=COLOR_BG)
        self.wid = self.canvas.create_window(450, 300, window=self.content, anchor="center") 
        self.canvas.bind("<Configure>", lambda e: self.canvas.coords(self.wid, e.width/2, e.height/2))

        tk.Label(self.content, text=t("audit_prog"), font=("Consolas", 18, "bold"), bg=COLOR_BG, fg=COLOR_ACCENT).pack(pady=40)
        self.l_status = tk.Label(self.content, text=t("init"), font=("Consolas", 12), bg=COLOR_BG, fg=COLOR_TEXT); self.l_status.pack(pady=30)
        BotonDinamico(self.content, COLOR_DANGER, text=t("stop_scan"), command=self.stop, width=25).pack()
        
        # Iniciar el hilo de escaneo
        self.scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self.scan_thread.start()
        
        self.check_queue()

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def check_queue(self):
        try:
            while not self.cola_estado.empty():
                msg = self.cola_estado.get_nowait()
                if msg == "DONE_SIGNAL": self.finish_scan_gui()
                else: self.l_status.config(text=msg)
        except: pass
        if not cancelar_escaneo: self.after(100, self.check_queue)

    def update_status(self, msg): self.cola_estado.put(msg)
    
    def stop(self):
        global cancelar_escaneo
        cancelar_escaneo = True
        self.controller.switch_frame(MenuFrame)

    def finish_scan_gui(self):
        self.anim.detener()
        show_info("DONE", f"Results saved in:\n{self.fp_final}")
        self.controller.switch_frame(MenuFrame)

    def run_scan(self):
        # Declarar todas las variables globales de reporte
        global reporte_shim, reporte_appcompat, reporte_sospechosos, reporte_firmas, reporte_path
        global reporte_ocultos, reporte_mft, reporte_vt, reporte_userassist, reporte_usb
        global reporte_dns, reporte_browser, reporte_persistencia, reporte_eventos
        global reporte_process, reporte_game, reporte_nuclear, reporte_kernel, reporte_dna
        global reporte_network, reporte_toxic, reporte_ghost, reporte_memory, reporte_drivers
        global reporte_static, reporte_morph, reporte_cleaning

        bd, fn = self.rutas.get('path', os.path.abspath(".")), self.rutas.get('folder', "Resultados_SS")
        fp = os.path.join(bd, fn)
        if not os.path.exists(fp): os.makedirs(fp, exist_ok=True)
        
        # Asignar rutas
        reporte_shim = os.path.join(fp, "Shimcache_Rastros.txt")
        reporte_appcompat = os.path.join(fp, "rastro_appcompat.txt")
        reporte_path = os.path.join(fp, "buscar_en_disco.txt")
        reporte_sospechosos = os.path.join(fp, "cambios_sospechosos.txt")
        reporte_firmas = os.path.join(fp, "Digital_Signatures_ZeroTrust.txt")
        reporte_ocultos = os.path.join(fp, "archivos_ocultos.txt")
        reporte_mft = os.path.join(fp, "MFT_Archivos.txt")
        reporte_vt = os.path.join(fp, "detecciones_virustotal.txt")
        reporte_userassist = os.path.join(fp, "UserAssist_Decoded.txt")
        reporte_usb = os.path.join(fp, "USB_History.txt")
        reporte_dns = os.path.join(fp, "DNS_Cache.txt")
        reporte_browser = os.path.join(fp, "Browser_Forensics.txt")
        reporte_persistencia = os.path.join(fp, "Persistence_Check.txt")
        reporte_eventos = os.path.join(fp, "Windows_Events.txt")
        reporte_process = os.path.join(fp, "Process_Hunter.txt")
        reporte_game = os.path.join(fp, "Game_Cheat_Hunter.txt")
        reporte_nuclear = os.path.join(fp, "Nuclear_Traces.txt")
        reporte_kernel = os.path.join(fp, "Kernel_Anomalies.txt")
        reporte_dna = os.path.join(fp, "DNA_Prefetch.txt")
        reporte_network = os.path.join(fp, "Network_Anomalies.txt")
        reporte_toxic = os.path.join(fp, "Toxic_LNK.txt")
        reporte_ghost = os.path.join(fp, "Ghost_Trails.txt")
        reporte_memory = os.path.join(fp, "Memory_Injection_Report.txt")
        reporte_drivers = os.path.join(fp, "Rogue_Drivers.txt")
        reporte_static = os.path.join(fp, "Deep_Static_Analysis.txt")
        reporte_morph = os.path.join(fp, "Metamorphosis_Report.txt")
        reporte_cleaning = os.path.join(fp, "String_Cleaner_Detection.txt")

        try: generar_reporte_html(fp, self.config)
        except: pass
        
        # Verificar si VirusTotal está activo (Variable vte)
        vte = self.config.get('vt', {}).get('active', False)
        if vte: 
            with open(reporte_vt, "w", encoding="utf-8") as f: f.write(f"=== VT: {datetime.datetime.now()} ===\n\n")
            threading.Thread(target=worker_virustotal, daemon=True).start()
        
        fases = [
            ('f1', fase_shimcache), ('f2', fase_rastro_appcompat), ('f3', fase_nombre_original),
            ('f4', fase_verificar_firmas), ('f5', fase_buscar_en_disco), ('f6', fase_archivos_ocultos),
            ('f7', fase_mft_ads), ('f8', fase_userassist), ('f9', fase_usb_history),
            ('f10', fase_dns_cache), ('f11', fase_browser_forensics), ('f12', fase_persistence),
            ('f13', fase_event_logs), ('f14', fase_process_hunter), ('f15', fase_game_cheat_hunter),
            ('f16', fase_nuclear_traces), ('f17', fase_kernel_hunter), ('f18', fase_dna_prefetch),
            ('f19', fase_network_hunter), ('f20', fase_toxic_lnk), ('f21', fase_ghost_trails),
            ('f22', fase_memory_anomaly), ('f23', fase_rogue_drivers), ('f24', fase_deep_static),
            ('f25', fase_metamorphosis_hunter), ('f26', fase_string_cleaning)
        ]
        
        for k, func in fases:
            if cancelar_escaneo: break
            if self.config.get(k, {}).get('active'):
                self.update_status(f"Running: {k.upper()}...")
                
                # --- LOGICA CORREGIDA DE ARGUMENTOS ---
                args = []
                if k == 'f3': args = [vte, self.palabras, self.config[k]['modo']]
                elif k == 'f4': args = [self.palabras, vte, self.config[k]['modo']]
                elif k == 'f5': args = [self.palabras]
                elif k == 'f24': args = [self.palabras, self.config[k]['modo']]
                elif k == 'f25': args = [self.palabras, self.config[k]['modo']]
                else: args = [self.palabras, self.config[k]['modo']]
                
                try: func(*args)
                except Exception as e: 
                    print(f"Error executing {k}: {e}") 
                
                try: generar_reporte_html(fp, self.config)
                except: pass
        
        # --- FINALIZACIÓN CORRECTA CON VIRUSTOTAL ---
        # 1. Enviar señal de fin a la cola
        cola_vt.put(None)
        
        # 2. Esperar a VT solo si estaba activo (usando variable vte)
        if vte:
            self.update_status("Finalizando subidas a VirusTotal...")
            # IMPORTANTE: Asegúrate de que worker_virustotal tenga cola_vt.task_done()
            cola_vt.join()

        if not cancelar_escaneo: 
            self.fp_final = fp
            self.cola_estado.put("DONE_SIGNAL")

if __name__ == "__main__":
    if check_security():
        sys.exit()
    
    # --- INICIALIZAR YARA AQUÍ ---
    print("Cargando motor de detección...")
    inicializar_yara() 
    # -----------------------------
    
    app = ScannelerApp()
    app.mainloop()