import os
import datetime
import pefile
import subprocess
import ctypes
import sys
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
        if ruta is None: break
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
    if cancelar_escaneo: return
    with open(reporte_shim, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== SHIMCACHE & EXTERNAL DEVICE TRACES: {datetime.datetime.now()} ===\n")
        f.write("Scanning for: Program execution history & USB/External drive launches.\n\n")
        try:
            ps = "$RegPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache'; $BinaryData = (Get-ItemProperty $RegPath).AppCompatCache; if ($BinaryData.Length -gt 0) { $StringData = [System.Text.Encoding]::Unicode.GetString($BinaryData); $Matches = [regex]::Matches($StringData, '([a-zA-Z]:\\\\[^\\x00]+)'); foreach ($m in $Matches) { $m.Value.Trim() } }"
            proc = subprocess.Popen(['powershell', '-command', ps], stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            if out:
                lines = set(out.splitlines())
                for l in lines:
                    l = l.strip(); l_upper = l.upper()
                    if not l: continue
                    is_external = False
                    if len(l) > 1 and l[1] == ':' and not l_upper.startswith("C:"): is_external = True
                    hit_keyword = any(p in l.lower() for p in palabras)
                    if is_external: f.write(f"[!!!] EXTERNAL USB/DRIVE: {l} (Sospechoso de carga externa)\n"); f.flush()
                    elif hit_keyword: f.write(f"[ALERT] KEYWORD MATCH: {l}\n"); f.flush()
                    elif modo == "Analizar Todo": f.write(f"RUTA: {l}\n"); f.flush()
        except Exception as e: f.write(f"Error reading ShimCache: {e}\n")

def fase_rastro_appcompat(palabras, modo):
    if cancelar_escaneo: return
    with open(reporte_appcompat, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== RASTRO APPCOMPAT: {datetime.datetime.now()} ===\n\n")
        r = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
        for h in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            try:
                with winreg.OpenKey(h, r) as k:
                    info_key = winreg.QueryInfoKey(k); num_values = info_key[1]
                    for i in range(num_values):
                        n, _, _ = winreg.EnumValue(k, i)
                        if modo == "Analizar Todo" or any(p in n.lower() for p in palabras): f.write(f"EXE: {n}\n"); f.flush()
            except: continue

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
    if cancelar_escaneo: return
    with open(reporte_ocultos, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== OCULTOS: {datetime.datetime.now()} ===\n\n")
        for r, _, as_ in os.walk("C:\\"):
            if cancelar_escaneo: break
            if "C:\\Windows" in r: continue
            for n in as_:
                ruta = os.path.join(r, n)
                if modo == "Analizar Todo" or any(p in n.lower() for p in palabras):
                    try:
                        if ctypes.windll.kernel32.GetFileAttributesW(ruta) & (2|4): f.write(f"OCULTO: {ruta}\n"); f.flush()
                    except: continue

def fase_mft_ads(palabras, modo):
    global cancelar_escaneo
    if cancelar_escaneo: return
    with open(reporte_mft, "w", encoding="utf-8", buffering=1) as f: 
        f.write(f"=== MFT & ADS: {datetime.datetime.now()} ===\n\n")
        targets = ["C:\\Users", "C:\\ProgramData", "C:\\Windows\\Temp"]
        for target in targets:
            if cancelar_escaneo: break
            try:
                cmd = f'Get-ChildItem -Path "{target}" -Recurse -File -ErrorAction SilentlyContinue | Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object {{ $_.Stream -ne ":$DATA" }} | ForEach-Object {{ "$($_.FileName):$($_.Stream)" }}'
                proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, creationflags=0x08000000)
                while True:
                    if cancelar_escaneo: proc.terminate(); break
                    l = proc.stdout.readline()
                    if not l and proc.poll() is not None: break
                    if l:
                        lc = l.strip()
                        if "Zone.Identifier" not in lc:
                            if lc and (modo == "Analizar Todo" or any(p in lc.lower() for p in palabras)): f.write(f"ADS: {lc}\n"); f.flush()
            except: pass

def fase_userassist(palabras, modo):
    if cancelar_escaneo: return
    with open(reporte_userassist, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== USERASSIST: {datetime.datetime.now()} ===\n\n")
        try:
            r = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r) as k_ua:
                num_subkeys = winreg.QueryInfoKey(k_ua)[0]
                for i in range(num_subkeys):
                    guid = winreg.EnumKey(k_ua, i)
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{r}\\{guid}\\Count") as k_c:
                            num_values = winreg.QueryInfoKey(k_c)[1]
                            for j in range(num_values):
                                n_rot, _, _ = winreg.EnumValue(k_c, j)
                                try:
                                    n_real = codecs.decode(n_rot, 'rot_13')
                                    if modo == "Analizar Todo" or any(p in n_real.lower() for p in palabras): f.write(f"EJECUTADO: {n_real}\n"); f.flush()
                                except: continue
                    except: continue
        except: pass

# --- FASE 9 (MASTER V2): USB, GHOST DRIVES & ENCRYPTION STATUS ---
def fase_usb_history(palabras, modo):
    if cancelar_escaneo: return
    print(f"[9/26] USB Forensics, Ghost LNKs & Encryption Hunter [DEEP SCAN]...")

    with open(reporte_usb, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== USB, ENCRYPTION & REMOVED DRIVES FORENSICS: {datetime.datetime.now()} ===\n\n")

        # ---------------------------------------------------------
        # 1. GHOST LNK HUNTER (DETECTAR EJECUCIONES DE USBS QUITADOS)
        # ---------------------------------------------------------
        f.write("--- 1. REMOVED DRIVE EVIDENCE (Ghost LNKs) ---\n")
        f.write("Scanning for: Shortcuts pointing to drives that are currently disconnected.\n")
        
        active_drives = [f"{d}:" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:")]
        f.write(f"Active Drives: {', '.join(active_drives)}\n\n")

        try:
            # Script PowerShell para analizar LNKs en Recent
            ps_lnk = r"""
            $Recent = [Environment]::GetFolderPath("Recent")
            $WScript = New-Object -ComObject WScript.Shell
            Get-ChildItem $Recent -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $Shortcut = $WScript.CreateShortcut($_.FullName)
                    $Target = $Shortcut.TargetPath
                    if ($Target -match "^([A-Z]:)") {
                        $Drive = $Matches[1]
                        Write-Output "$($_.Name)|$Target|$Drive"
                    }
                } catch {}
            }
            """
            proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", ps_lnk], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()

            ghost_found = False
            if out:
                for line in out.splitlines():
                    if "|" in line:
                        parts = line.split("|")
                        if len(parts) >= 3:
                            lnk_name = parts[0]
                            target_path = parts[1]
                            drive_letter = parts[2]

                            # Si la unidad del LNK no está conectada actualmente -> EVIDENCIA
                            if drive_letter not in active_drives:
                                tag = "[EVIDENCE OF REMOVED USB]"
                                is_cheat = any(p in target_path.lower() for p in palabras)
                                
                                if is_cheat: tag = "[!!!] CONFIRMED CHEAT ON REMOVED USB"
                                
                                if modo == "Analizar Todo" or is_cheat or target_path.lower().endswith((".exe", ".bat", ".dll", ".sys")):
                                    f.write(f"{tag}\n")
                                    f.write(f"      Shortcut: {lnk_name}\n")
                                    f.write(f"      Points to: {target_path}\n")
                                    f.write(f"      Status: DRIVE {drive_letter} DISCONNECTED (Removed after execution)\n")
                                    f.write("-" * 40 + "\n")
                                    ghost_found = True
            
            if not ghost_found:
                f.write("[OK] No execution traces from removed drives found in Recent.\n")

        except Exception as e:
            f.write(f"[ERROR] Scanning Ghost LNKs: {e}\n")

        # ---------------------------------------------------------
        # 2. ENCRYPTION & BITLOCKER STATUS (LO QUE PEDISTE)
        # ---------------------------------------------------------
        f.write("\n--- 2. ENCRYPTED VOLUMES & BITLOCKER STATUS ---\n")
        try:
            # manage-bde es la herramienta nativa para ver el estado de cifrado
            cmd_bde = 'manage-bde -status'
            proc_bde = subprocess.Popen(cmd_bde, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000)
            out_bde, _ = proc_bde.communicate()
            
            if out_bde:
                # Parsear la salida de manage-bde para hacerla legible y buscar alertas
                volumes = out_bde.split("Volumen ") # Separar por volumen si está en español/inglés
                if len(volumes) < 2: volumes = out_bde.split("Volume ")

                encrypted_found = False
                for vol in volumes:
                    if not vol.strip(): continue
                    
                    vol_info = vol.lower()
                    # Detectar estado de protección
                    is_encrypted = "protección activada" in vol_info or "protection on" in vol_info
                    is_locked = "bloqueada" in vol_info or "locked" in vol_info
                    
                    # Ignorar C: si se quiere, o reportar todo. Reportamos todo para seguridad.
                    if is_encrypted:
                        header = "[!!!] ENCRYPTED VOLUME FOUND"
                        # Si está encriptado pero DESBLOQUEADO, se puede leer el contenido AHORA.
                        if "desbloqueada" in vol_info or "unlocked" in vol_info:
                             header = "[!!!] ENCRYPTED CONTAINER (OPEN/UNLOCKED)"
                        
                        f.write(f"{header}\n")
                        # Limpiamos las líneas vacías para que quede prolijo
                        clean_vol = "\n".join([line.strip() for line in vol.splitlines() if line.strip()])
                        f.write(f"      {clean_vol.replace(chr(10), chr(10)+'      ')}\n") # Indentación
                        f.write("-" * 40 + "\n")
                        encrypted_found = True
                
                if not encrypted_found:
                    f.write("[INFO] No active BitLocker encrypted volumes found.\n")
            else:
                f.write("[INFO] Unable to query BitLocker status (Service might be disabled).\n")

        except Exception as e:
            f.write(f"[ERROR] Checking encryption: {e}\n")

        # ---------------------------------------------------------
        # 3. HISTORIAL DE DISPOSITIVOS (REGISTRO)
        # ---------------------------------------------------------
        f.write("\n--- 3. USB DEVICE CONNECTION HISTORY (Registry) ---\n")
        try:
            r_usb = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r_usb) as k_usb:
                for i in range(winreg.QueryInfoKey(k_usb)[0]):
                    dtype = winreg.EnumKey(k_usb, i)
                    try:
                        r_dev = f"{r_usb}\\{dtype}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r_dev) as k_dev:
                            num_devs = winreg.QueryInfoKey(k_dev)[0]
                            for j in range(num_devs):
                                serial = winreg.EnumKey(k_dev, j)
                                try:
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{r_dev}\\{serial}") as k_inst:
                                        fname = "Unknown"
                                        try: fname, _ = winreg.QueryValueEx(k_inst, "FriendlyName")
                                        except: pass
                                        
                                        info = f"DEVICE: {fname}\n      SERIAL: {serial}\n      TYPE: {dtype}"
                                        
                                        # Detectar hardware de cheats (DMA, Arduino, etc)
                                        if any(k in fname.lower() for k in ["arduino", "rubber", "ducky", "teensy", "dma", "capcom"]):
                                            f.write(f"[!!!] SUSPICIOUS HARDWARE DETECTED:\n{info}\n\n")
                                        elif modo == "Analizar Todo":
                                            f.write(f"[HISTORY] {info}\n\n")
                                except: continue
                    except: continue
        except: f.write("Error reading USB Registry.\n")

        # ---------------------------------------------------------
        # 4. UNIDADES MAPEADAS (RED)
        # ---------------------------------------------------------
        f.write("\n--- 4. MAPPED NETWORK DRIVES ---\n")
        try:
            proc_net = subprocess.Popen('net use', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000)
            out_net, _ = proc_net.communicate()
            if "OK" in out_net or "Disconnected" in out_net:
                f.write(out_net)
            else:
                f.write("[OK] No active network drives mapped.\n")
        except: pass

def fase_dns_cache(palabras, modo):
    if cancelar_escaneo: return
    with open(reporte_dns, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== DNS CACHE: {datetime.datetime.now()} ===\n\n")
        try:
            out = subprocess.check_output("ipconfig /displaydns", shell=True, text=True, errors='ignore')
            for l in out.splitlines():
                l = l.strip()
                if "Nombre de registro" in l or "Record Name" in l:
                    parts = l.split(":")
                    if len(parts) > 1:
                        dom = parts[1].strip()
                        if dom and (modo == "Analizar Todo" or any(p in dom.lower() for p in palabras)): f.write(f"DOMAIN: {dom}\n"); f.flush()
        except: pass

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
    if cancelar_escaneo: return
    cmds = [("LOG_WIPED", "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object @{N='Date';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Message; Get-WinEvent -FilterHashtable @{LogName='System'; ID=104} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object @{N='Date';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Message"), ("LOGIN_OK", "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object @{N='Date';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Message"), ("LOGIN_FAIL", "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object @{N='Date';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Message"), ("NEW_SVC", "Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object @{N='Date';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Message"), ("DEFENDER_THREATS", "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1116,1117,1119} -ErrorAction SilentlyContinue | Select-Object @{N='Date';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Message"), ("DEFENDER_EXCLUSIONS", "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=5007} -ErrorAction SilentlyContinue | Where-Object {$_.Message -like '*Exclusion*'} | Select-Object @{N='Date';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Message")]
    with open(reporte_eventos, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== EVENTS INVESTIGATION: {datetime.datetime.now()} ===\n"); f.write(f"IDs Monitoreados: 1102, 104 (Wipe), 4624/25 (Login), 7045 (Svc), 1116/17/19/5007 (Defender)\n\n")
        for tit, ps in cmds:
            f.write(f"--- {tit} ---\n")
            try:
                proc = subprocess.Popen(f'powershell -Command "{ps} | Format-List"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, encoding='cp850', errors='ignore'); out, err = proc.communicate()
                if "No se encontraron" in err or "NoMatchingEventsFound" in err: f.write("   [OK] No suspicious events found in this category.\n")
                elif out:
                    lines = out.splitlines(); block = []; found = False
                    for l in lines:
                        l = l.strip()
                        if not l:
                            txt_blk = " | ".join(block)
                            if txt_blk:
                                if modo == "Analizar Todo" or any(p in txt_blk.lower() for p in palabras) or "LOG_WIPED" in tit:
                                    pref = "   [!!!] " if ("LOG_WIPED" in tit or "DEFENDER" in tit) else "   "
                                    for bl in block: f.write(f"{pref}{bl}\n")
                                    f.write("   " + "-"*40 + "\n"); found = True
                            block = []
                        else: block.append(l)
                    if block:
                         txt_blk = " | ".join(block)
                         if modo == "Analizar Todo" or any(p in txt_blk.lower() for p in palabras) or "LOG_WIPED" in tit:
                             pref = "   [!!!] " if "LOG_WIPED" in tit else "   "; 
                             for bl in block: f.write(f"{pref}{bl}\n")
                             found = True
                    if not found and modo != "Analizar Todo": f.write("   [OK] No matching keywords found in logs.\n")
            except Exception as e: f.write(f"   [ERROR] Failed to extract events: {str(e)}\n")
            f.write("\n")

def fase_process_hunter(palabras, modo):
    if cancelar_escaneo: return
    sys_bins = {"svchost.exe": "c:\\windows\\system32", "csrss.exe": "c:\\windows\\system32", "winlogon.exe": "c:\\windows\\system32", "services.exe": "c:\\windows\\system32", "lsass.exe": "c:\\windows\\system32", "smss.exe": "c:\\windows\\system32", "explorer.exe": "c:\\windows", "taskmgr.exe": "c:\\windows\\system32", "conhost.exe": "c:\\windows\\system32"}
    with open(reporte_process, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== PROCESS HUNTER: {datetime.datetime.now()} ===\n\n"); f.write("--- LIVE RAM ANALYSIS ---\n")
        try:
            proc = subprocess.Popen('wmic process get ProcessId,Name,ExecutablePath /format:csv', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000); out, _ = proc.communicate()
            if out:
                lines = out.splitlines()
                for l in lines:
                    if not l.strip(): continue
                    parts = l.split(","); 
                    if len(parts) < 2: continue
                    try: path = parts[1].strip(); name = parts[2].strip(); pid = parts[3].strip()
                    except: continue
                    if name.lower() == "name": continue 
                    susp = False; reason = ""
                    if name.lower() in sys_bins:
                        expected = sys_bins[name.lower()]
                        if path and not path.lower().startswith(expected): susp = True; reason = f"MASQUERADING: Se espera en {expected} pero corre en {path}"
                    if path and ("\\temp\\" in path.lower() or "\\appdata\\" in path.lower()):
                        if modo == "Analizar Todo":
                             if not susp: pass 
                    info = f"PID: {pid} | NAME: {name} | PATH: {path}"
                    if susp: f.write(f"[!!!] CRITICAL: {name} (PID {pid})\n      > {reason}\n"); f.flush()
                    elif modo=="Analizar Todo" or any(p in info.lower() for p in palabras): f.write(f"[LIVE] {info}\n"); f.flush()
        except Exception as e: f.write(f"Error reading processes: {e}\n")
        f.write("\n--- DEAD PROCESSES (Last 45 mins) ---\n")
        try:
            ps = "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4689} -ErrorAction SilentlyContinue | Where-Object {$_.TimeCreated -ge (Get-Date).AddMinutes(-45)} | Select-Object @{N='Time';E={$_.TimeCreated.ToString('HH:mm:ss')}}, @{N='Name';E={$_.Properties[0].Value}} | Format-Table -HideTableHeaders"
            proc = subprocess.Popen(f'powershell -NoProfile -Command "{ps}"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, encoding='cp850', errors='ignore', creationflags=0x08000000); out, _ = proc.communicate()
            if out:
                unique_procs = set()
                for l in out.splitlines():
                    clean_l = l.strip()
                    if clean_l: unique_procs.add(clean_l)
                for p in unique_procs:
                     if modo == "Analizar Todo" or any(k in p.lower() for k in palabras): f.write(f"[DEAD] {p}\n"); f.flush()
        except: pass

def fase_game_cheat_hunter(palabras, modo):
    if cancelar_escaneo: return
    print(f"[15/24] Game Cheat Hunter (YARA POWERED) [ULTRA DEEP SCAN]...")
    
    # Lista negra interna para nombres de archivos (Metadata)
    internal_blackilst = ["cheat engine", "process hacker", "x64dbg", "ollydbg", "dnspy", "injector", "ks dumper", "http debugger", "netlimiter"]

    with open(reporte_game, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== GAME CHEAT HUNTER (YARA): {datetime.datetime.now()} ===\n")
        
        if GLOBAL_YARA_RULES is None:
             f.write("[ERROR] YARA Rules not loaded. Skipping deep content scan.\n\n")
        else:
             f.write(f"Engine: YARA Active | Rules Loaded.\n\n")

        hot_paths = [os.path.join(os.environ["USERPROFILE"], "Downloads"), 
                     os.path.join(os.environ["USERPROFILE"], "Desktop"), 
                     os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Temp"),
                     os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming")]

        for target_dir in hot_paths:
            if not os.path.exists(target_dir): continue
            f.write(f"--- Scanning: {target_dir} ---\n")
            
            try:
                # Escaneamos los 80 archivos más recientes
                with os.scandir(target_dir) as entries:
                    files = sorted([e.path for e in entries if e.is_file() and e.name.lower().endswith(('.exe', '.dll', '.tmp', '.sys', '.bin', '.dat'))], key=os.path.getmtime, reverse=True)[:80]
                
                for file_path in files:
                    if cancelar_escaneo: break
                    file_name = os.path.basename(file_path)
                    suspicious = False
                    reason = ""
                    entropy_val = 0
                    
                    try:
                        # 1. Lectura y Entropía
                        with open(file_path, "rb") as bf:
                            content = bf.read(15 * 1024 * 1024) # Leer primeros 15MB
                            
                        entropy_val = calculate_entropy(content)
                        if entropy_val > 7.4: 
                            suspicious = True
                            reason = f"HIGH ENTROPY ({entropy_val:.2f}): Possible Packed/Encrypted Hack"

                        # 2. ESCANEO CON YARA (Reemplaza el bucle for gigante anterior)
                        if GLOBAL_YARA_RULES:
                            try:
                                # Escaneamos el contenido en memoria
                                matches = GLOBAL_YARA_RULES.match(data=content)
                                if matches:
                                    suspicious = True
                                    reglas_activadas = [m.rule for m in matches]
                                    # Obtener detalles de qué strings detectó (opcional)
                                    reason = f"YARA MATCH: {', '.join(reglas_activadas)}"
                            except Exception as yara_e:
                                print(f"Yara error on {file_name}: {yara_e}")

                        # 3. Análisis de Metadata (PE)
                        if not suspicious:
                            try:
                                pe = pefile.PE(file_path, fast_load=True)
                                if hasattr(pe, 'FileInfo'):
                                    for file_info in pe.FileInfo:
                                        if hasattr(file_info, 'StringTable'):
                                            for st in file_info.StringTable:
                                                for k, v in st.entries.items():
                                                    val_dec = v.decode('utf-8', 'ignore').lower()
                                                    for bad in internal_blackilst:
                                                        if bad in val_dec: 
                                                            suspicious = True
                                                            reason = f"METADATA MATCH: {val_dec}"
                                                            break
                                pe.close()
                            except: pass

                    except Exception as e: pass

                    if suspicious: 
                        f.write(f"[!!!] CHEAT DETECTED: {file_name}\n      Path: {file_path}\n      Entropy: {entropy_val:.2f}\n      Reason: {reason}\n" + "-"*50 + "\n")
                        f.flush()
                    elif modo == "Analizar Todo": 
                        f.write(f"[CLEAN] {file_name} (Ent: {entropy_val:.2f})\n")
                        f.flush()
            except: pass

def fase_nuclear_traces(palabras, modo):
    if cancelar_escaneo: return
    print(f"[16/24] Nuclear Traces (BAM & Pipes) [DEFINITIVE]...")
    with open(reporte_nuclear, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== NUCLEAR TRACES: {datetime.datetime.now()} ===\n\n")
        suspicious_pipes = ["cheat", "hack", "injector", "loader", "esp", "aim", "battleye", "easyanticheat", "faceit", "esea", "vanguard", "overlay", "hook", "auth"]
        f.write("--- LIVE NAMED PIPES ---\n")
        try:
            pipes = os.listdir(r'\\.\pipe\\')
            for pipe in pipes:
                pipe_lower = pipe.lower()
                if any(s in pipe_lower for s in suspicious_pipes): f.write(f"[PIPE DETECTED] Posible Hack Comms: {pipe}\n"); f.flush()
                if len(pipe) > 20 and "-" in pipe and "{" not in pipe and "com" not in pipe:
                     if modo == "Analizar Todo": f.write(f"[SUSPICIOUS PIPE] Random/UUID Pattern: {pipe}\n"); f.flush()
        except Exception as e: f.write(f"Error scanning pipes: {e}\n")
        f.write("\n--- BAM EXECUTION HISTORY ---\n")
        try:
            bam_path = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bam_path) as k_bam:
                num_sids = winreg.QueryInfoKey(k_bam)[0]
                for i in range(num_sids):
                    sid = winreg.EnumKey(k_bam, i)
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{bam_path}\\{sid}") as k_user:
                            num_vals = winreg.QueryInfoKey(k_user)[1]
                            for j in range(num_vals):
                                exe_path, _, _ = winreg.EnumValue(k_user, j)
                                if "\\Device\\HarddiskVolume" in exe_path: exe_path = exe_path.replace("\\Device\\HarddiskVolume", "Volume")
                                exe_lower = exe_path.lower(); hit = False; reason = ""
                                if "temp" in exe_lower or "appdata" in exe_lower:
                                    if any(k in exe_lower for k in ["cheat", "loader", "inject", "priv", "vip"]): hit = True; reason = "Keyword in Temp Path"
                                    elif modo == "Analizar Todo" and ".exe" in exe_lower: f.write(f"[BAM HISTORY] Executed from Temp: {exe_path}\n"); f.flush(); continue
                                if "volume" in exe_lower and "program files" not in exe_lower and "windows" not in exe_lower: f.write(f"[BAM EXTERNAL] Executed from external drive: {exe_path}\n"); f.flush(); continue
                                if any(p in exe_lower for p in palabras) or any(s in exe_lower for s in ["aimbot", "esp", "wallhack"]): hit = True; reason = "Keyword Match"
                                if hit: f.write(f"[!!!] EXECUTION PROVEN: {exe_path}\n      (Este archivo se ejecuto en el pasado)\n"); f.flush()
                    except: pass
        except Exception as e: f.write(f"Error accessing BAM registry: {e}\n")

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
    if cancelar_escaneo: return
    print(f"[18/24] DNA & Prefetch Hunter (Native Bridge Mode) [FORENSIC]...")
    
    suspicious_imports = [b"WriteProcessMemory", b"CreateRemoteThread", b"VirtualAllocEx", b"OpenProcess", 
                          b"ReadProcessMemory", b"LdrLoadDll", b"NtCreateThreadEx", b"RtlCreateUserThread", b"SetWindowsHookExA"]
    
    # Rutas para DNA
    hot_paths = [
        os.path.join(os.environ["USERPROFILE"], "Downloads"),
        os.path.join(os.environ["USERPROFILE"], "Desktop"),
        os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Temp")
    ]

    try: 
        # Usamos el Context Manager para desactivar la redireccion (vital para Prefetch)
        with DisableFileSystemRedirection():
            
            with open(reporte_dna, "w", encoding="utf-8", buffering=1) as f:
                f.write(f"=== DNA & PREFETCH SCAN: {datetime.datetime.now()} ===\n")
                f.write("Strategy: Native CMD access to bypass 32-bit redirection.\n\n")
                
                # --- PARTE 1: DNA (Imports) ---
                f.write("--- EXECUTABLE DNA ANALYSIS (Injection Capabilities) ---\n")
                for target_dir in hot_paths:
                    if not os.path.exists(target_dir): continue
                    try:
                        # Escaneo rapido de ejecutables
                        with os.scandir(target_dir) as entries:
                            files = [e.path for e in entries if e.is_file() and e.name.lower().endswith('.exe')]
                        
                        for file_path in files:
                            if cancelar_escaneo: break
                            file_name = os.path.basename(file_path)
                            try:
                                pe = pefile.PE(file_path, fast_load=True)
                                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                                injection_score = 0
                                found_apis = []
                                
                                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                                        for imp in entry.imports:
                                            if imp and imp.name and imp.name in suspicious_imports:
                                                injection_score += 1
                                                found_apis.append(imp.name.decode('utf-8'))
                                pe.close()
                                
                                if injection_score >= 2:
                                    f.write(f"[!!!] INJECTOR DNA DETECTED: {file_name}\n")
                                    f.write(f"      Path: {file_path}\n")
                                    f.write(f"      Capabilities: {', '.join(found_apis)}\n")
                                    f.write("-" * 50 + "\n")
                                    f.flush()
                            except: pass
                    except: pass
                
                # --- PARTE 2: PREFETCH (CORREGIDA) ---
                f.write("\n--- WINDOWS PREFETCH CACHE (Execution History) ---\n")
                
                pf_files = []
                prefetch_raw_list = ""
                
                # INTENTO 1: USAR CMD NATIVO (SYSNATIVE) - ESTO ARREGLA EL PROBLEMA
                # Buscamos el cmd.exe real de 64 bits para ver la carpeta real
                try:
                    sysnative = r"C:\Windows\Sysnative\cmd.exe"
                    shell = sysnative if os.path.exists(sysnative) else "cmd.exe"
                    
                    # Ejecutamos 'dir /b' directamente sobre la carpeta
                    cmd_line = [shell, "/c", r"dir /b /a-d C:\Windows\Prefetch"]
                    
                    proc = subprocess.Popen(cmd_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
                    out, err = proc.communicate()
                    
                    if out:
                        prefetch_raw_list = out
                        f.write(f"[DEBUG] Native CMD Access Successful. Bytes read: {len(out)}\n")
                    elif err:
                        f.write(f"[DEBUG] CMD Error: {err.strip()}\n")
                        
                except Exception as e:
                    f.write(f"[DEBUG] Subprocess failed: {e}\n")

                # Si falló el CMD, intentamos Python directo (Fallback)
                if not prefetch_raw_list:
                    try:
                        pf_list = os.listdir(r"C:\Windows\Prefetch")
                        prefetch_raw_list = "\n".join(pf_list)
                    except: pass

                # PROCESAR LISTA
                if prefetch_raw_list:
                    pf_files = [x.strip() for x in prefetch_raw_list.splitlines() if x.strip().upper().endswith(".PF")]
                    
                    # Ordenar por fecha (truco: intentar obtener fecha del archivo real)
                    # Como no tenemos paths completos faciles, los procesamos como vienen o intentamos sortearlos
                    # Para velocidad, procesamos la lista tal cual
                    
                    keywords = ["CHEAT", "HACK", "INJECTOR", "LOADER", "ESP", "AIM", "SPOOFER", "XENOS", "PROCESS", "DSC", "DISCORD", "STEAM"]
                    pf_hits = 0
                    
                    f.write(f"Total Prefetch Files Found: {len(pf_files)}\n\n")
                    
                    for pf in pf_files:
                        if cancelar_escaneo: break
                        pf_upper = pf.upper()
                        
                        # Extraer nombre del EXE (PREFETCH es: NOMBRE.EXE-HASH.pf)
                        exe_part = pf_upper.split("-")[0]
                        
                        hit = False
                        if any(k in exe_part for k in keywords): hit = True
                        if any(p.upper() in exe_part for p in palabras): hit = True
                        
                        if hit or modo == "Analizar Todo":
                            marker = "[!!!]" if hit else "[INFO]"
                            f.write(f"{marker} {pf}\n")
                            pf_hits += 1
                    
                    if pf_hits == 0 and modo != "Analizar Todo":
                        f.write("[OK] No suspicious execution history found in Prefetch.\n")
                else:
                    f.write("[ERROR] COULD NOT READ PREFETCH FOLDER.\n")
                    f.write("Possibilities:\n")
                    f.write("1. Not running as Administrator.\n")
                    f.write("2. System cleaner wiped the folder.\n")

    except Exception as e:
        print(f"Error fatal en fase DNA: {e}")
        
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
    # --- 1. ARGUMENT EATER (Anti-Crash) ---
    try:
        palabras = args[0]
        modo = "Normal"
        if len(args) > 1 and isinstance(args[-1], str):
            modo = args[-1]
    except: return

    # --- 2. IMPORTS DE EMERGENCIA ---
    import os
    import time
    import datetime
    import math
    from collections import Counter

    # --- 3. PROTECCIÓN VARIABLES GLOBALES ---
    try:
        global cancelar_escaneo
        if 'cancelar_escaneo' not in globals(): cancelar_escaneo = False
    except: cancelar_escaneo = False

    try:
        global HISTORIAL_RUTAS
        if 'HISTORIAL_RUTAS' not in globals(): 
            HISTORIAL_RUTAS = {'path': os.path.abspath("."), 'folder': "Resultados_SS"}
    except: 
        HISTORIAL_RUTAS = {'path': os.path.abspath("."), 'folder': "Resultados_SS"}

    # --- 4. EJECUCIÓN ---
    try:
        if cancelar_escaneo: return

        print(f"[24/25] Deep Static Heuristics (YARA POWERED) [GOD-TIER]...")

        def internal_entropy_calc(data):
            if not data: return 0
            try:
                counts = Counter(data)
                length = len(data)
                entropy = 0
                for count in counts.values():
                    p_x = count / length
                    if p_x > 0: entropy += - p_x * math.log(p_x, 2)
                return entropy
            except: return 0

        global reporte_static
        if not reporte_static: reporte_static = "Deep_Static_Analysis.txt"
        base_path = HISTORIAL_RUTAS.get('path', os.path.abspath("."))
        folder_name = HISTORIAL_RUTAS.get('folder', "Resultados_SS")
        
        full_folder = os.path.join(base_path, folder_name)
        if not os.path.exists(full_folder):
            try: os.makedirs(full_folder)
            except: pass
            
        reporte_static = os.path.join(full_folder, "Deep_Static_Analysis.txt")

        try:
            u = os.environ.get("USERPROFILE", "C:\\")
            hunt_zones = [
                os.path.join(u, "Desktop"),
                os.path.join(u, "Downloads"),
                os.path.join(u, "AppData", "Local", "Temp"),
                os.path.join(u, "AppData", "Roaming")
            ]
        except: hunt_zones = ["C:\\"]

        # [MODIFICADO] Lista 'bad_genes' eliminada a favor de YARA

        MAX_FILE_SIZE_MB = 30
        MAX_SCAN_TIME = 10
        start_time = time.time()

        with open(reporte_static, "w", encoding="utf-8", buffering=1) as f:
            f.write(f"=== DEEP STATIC HEURISTICS: {datetime.datetime.now()} ===\n")
            f.write("Mode: Universal Arguments (*args) + YARA Engine.\n\n")
            
            # Verificación de YARA
            yara_active = False
            if 'GLOBAL_YARA_RULES' in globals() and GLOBAL_YARA_RULES:
                yara_active = True
                f.write("Status: YARA Rules Loaded [ACTIVE]\n\n")
            else:
                f.write("Status: YARA Rules NOT Loaded [LIMITED MODE - ENTROPY ONLY]\n\n")

            scanned = 0
            
            for zone in hunt_zones:
                if not os.path.exists(zone): continue
                if time.time() - start_time > MAX_SCAN_TIME: 
                    f.write("\nTime limit.\n"); break

                try:
                    for root, dirs, files in os.walk(zone):
                        if cancelar_escaneo: break
                        if time.time() - start_time > MAX_SCAN_TIME: break
                        
                        if any(x in root.lower() for x in ["windows", "microsoft", "google", "common files"]): continue

                        for filename in files:
                            if filename.lower().endswith((".exe", ".dll", ".sys", ".tmp")):
                                filepath = os.path.join(root, filename)
                                
                                try:
                                    if os.path.getsize(filepath) > (MAX_FILE_SIZE_MB * 1024 * 1024): continue
                                except: continue

                                if "microsoft" in filename.lower() or "setup" in filename.lower(): continue

                                try:
                                    with open(filepath, "rb") as target_file:
                                        data = target_file.read(2 * 1024 * 1024)
                                        if not data: continue
                                        
                                        scanned += 1
                                        score = 0
                                        reasons = []

                                        # 1. ENTROPÍA
                                        entropy = internal_entropy_calc(data)
                                        if entropy > 7.2:
                                            score += 2
                                            reasons.append(f"HIGH ENTROPY ({entropy:.2f})")

                                        # 2. [MODIFICADO] MOTOR YARA
                                        if yara_active:
                                            try:
                                                matches = GLOBAL_YARA_RULES.match(data=data)
                                                if matches:
                                                    for match in matches:
                                                        # Asignar peso según la severidad de la regla
                                                        rule_name = str(match)
                                                        if rule_name == "Inyeccion_y_Memoria":
                                                            score += 5
                                                            reasons.append("YARA: Critical Injection APIs")
                                                        elif rule_name == "Cheat_Strings_Genericos":
                                                            score += 4
                                                            reasons.append("YARA: Cheat Keywords")
                                                        elif rule_name == "Sus_Config_Files":
                                                            score += 3
                                                            reasons.append("YARA: Hack Config Pattern")
                                                        else:
                                                            score += 2
                                                            reasons.append(f"YARA: {rule_name}")
                                            except: pass
                                        
                                        # 3. HEURÍSTICA DE NOMBRE
                                        name_no_ext = filename.rsplit('.', 1)[0]
                                        if len(name_no_ext) < 5 and (name_no_ext.isdigit() or len(name_no_ext) <= 2):
                                            reasons.append("SHORT/NUMERIC NAME")
                                            score += 2

                                        # REPORTE
                                        if score >= 4:
                                            f.write(f"[!!!] HIDDEN THREAT: {filename}\n      Path: {filepath}\n      Ind: {', '.join(reasons)}\n" + "-"*40 + "\n"); f.flush()
                                except: pass
                except: pass
            
            f.write(f"\nScan done. Scanned: {scanned}")

    except Exception as e:
        print(f"CRITICAL ERROR F32: {e}")

def fase_metamorphosis_hunter(palabras, modo, target_file=None):
    if cancelar_escaneo: return
    print(f"[25/25] Metamorphosis Hunter (Speed Optimized + Timestamps) [NUCLEAR]...")
    
    # Variable de tiempo para evitar el error "start_time not defined"
    start_time = time.time()
    
    global reporte_morph
    if not reporte_morph: reporte_morph = "Metamorphosis_Report.txt"

    base_path = HISTORIAL_RUTAS.get('path', os.path.abspath("."))
    folder_name = HISTORIAL_RUTAS.get('folder', "Resultados_SS")
    reporte_morph_path = os.path.join(base_path, folder_name, reporte_morph)

    files_to_analyze = []
    if target_file and os.path.exists(target_file):
        files_to_analyze.append(target_file)
        scan_mode = "TARGETED (User Selected File)"
    else:
        scan_mode = "AUTO (Hot Zones Scan)"
        user_profile = os.environ["USERPROFILE"]
        scan_dirs = [
            os.path.join(user_profile, "Desktop"),
            os.path.join(user_profile, "Downloads"),
            os.path.join(user_profile, "AppData", "Local", "Temp")
        ]
        onedrive_desktop = os.path.join(user_profile, "OneDrive", "Desktop")
        if os.path.exists(onedrive_desktop): scan_dirs.append(onedrive_desktop)

        for directory in scan_dirs:
            if os.path.exists(directory):
                try:
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            if entry.is_file() and entry.name.lower().endswith(".exe"):
                                files_to_analyze.append(entry.path)
                except: pass

    suspicious_keywords = ["vencord", "installer", "setup", "update", "launcher", "client", "discord", "cheat", "hack", "loader"]
    
    # --- 1. PRE-CARGA DE EJECUCION (PREFETCH) ---
    prefetch_map = {}
    try:
        sysnative_prefetch = r"C:\Windows\Sysnative\Prefetch"
        real_prefetch = sysnative_prefetch if os.path.exists(sysnative_prefetch) else r"C:\Windows\Prefetch"
        if os.path.exists(real_prefetch):
            with os.scandir(real_prefetch) as entries:
                for entry in entries:
                    if entry.name.upper().endswith(".PF"):
                        exe_name = entry.name.split("-")[0].lower()
                        exec_time = entry.stat().st_mtime
                        if exe_name not in prefetch_map or exec_time > prefetch_map[exe_name]:
                            prefetch_map[exe_name] = exec_time
    except: pass

    # --- 2. PRE-CARGA MASIVA DE USN JOURNAL (OPTIMIZACION CRITICA) ---
    usn_db = {} 
    try:
        proc = subprocess.Popen('fsutil usn readjournal C: csv', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, errors='ignore', creationflags=0x08000000)
        start_read = time.time()
        while (time.time() - start_read) < 2.5: 
            line = proc.stdout.readline()
            if not line: break
            parts = line.split(',')
            if len(parts) > 6:
                fname = parts[-1].strip().lower()
                if fname.endswith(".exe"):
                    reason = parts[5].strip()
                    timestamp = parts[4].strip()
                    if fname not in usn_db: usn_db[fname] = []
                    usn_db[fname].append((timestamp, reason))
        proc.terminate()
    except: pass

    with open(reporte_morph_path, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== METAMORPHOSIS FORENSICS (SPEED MODE): {datetime.datetime.now()} ===\n")
        f.write(f"Mode: {scan_mode}\n")
        f.write(f"Files Queued: {len(files_to_analyze)}\n")
        f.write(f"USN Journal Cache: {len(usn_db)} executables tracked.\n\n")

        files_checked = 0
        detections = 0
        
        for filepath in files_to_analyze:
            if cancelar_escaneo: break
            if not target_file and files_checked > 2000: break 

            try:
                filename = os.path.basename(filepath)
                name_lower = filename.lower()
                
                should_scan = False
                if target_file: should_scan = True
                elif modo == "Analizar Todo": should_scan = True
                elif any(s in name_lower for s in suspicious_keywords): should_scan = True
                elif any(p in name_lower for p in palabras): should_scan = True
                elif "desktop" in filepath.lower() or "downloads" in filepath.lower(): should_scan = True
                
                if not should_scan: continue

                files_checked += 1
                
                stats = os.stat(filepath)
                current_size = stats.st_size
                mod_time = stats.st_mtime 
                mod_dt = datetime.datetime.fromtimestamp(mod_time)
                
                evidence = []
                score = 0
                
                # A. PARADOJA TEMPORAL (CON HORAS EXACTAS)
                if name_lower in prefetch_map:
                    last_exec_ts = prefetch_map[name_lower]
                    last_exec_dt = datetime.datetime.fromtimestamp(last_exec_ts)
                    
                    diff = mod_time - last_exec_ts
                    
                    if diff > 5:
                        # Formateamos las horas para mostrarlas claras
                        exec_str = last_exec_dt.strftime('%Y-%m-%d %H:%M:%S')
                        mod_str = mod_dt.strftime('%Y-%m-%d %H:%M:%S')
                        
                        evidence.append(f"[TIMELINE PARADOX] Integrity Violation:")
                        evidence.append(f"   > EXECUTION TIME:   {exec_str} (Last Run)")
                        evidence.append(f"   > MODIFICATION TIME:{mod_str} (Disk Write)")
                        evidence.append(f"   > DELTA: File changed {int(diff)} seconds AFTER execution.")
                        score += 10 

                # B. CONSULTA A LA DB EN MEMORIA
                if name_lower in usn_db:
                    history = usn_db[name_lower]
                    seen_truncate = False
                    seen_extend = False
                    
                    for timestamp, reason in history:
                        if "DATA_TRUNCATION" in reason:
                            evidence.append(f"[{timestamp}] USN: SIZE RESET (Emptied)")
                            seen_truncate = True
                            score += 2
                        if "DATA_EXTEND" in reason:
                            evidence.append(f"[{timestamp}] USN: SIZE INCREASE")
                            seen_extend = True
                            score += 1
                        if "DATA_OVERWRITE" in reason:
                             if score > 0: evidence.append(f"[{timestamp}] USN: OVERWRITE")
                             score += 1

                    if seen_truncate and seen_extend:
                        evidence.append("[CONCLUSION] Hot-Swap Sequence Detected (Truncate + Extend).")
                        score += 5

                threshold = 3 if target_file else 4
                if score >= threshold:
                    detections += 1
                    f.write(f"[!!!] ANOMALY DETECTED: {filename}\n")
                    f.write(f"      Path: {filepath}\n")
                    f.write(f"      Size: {current_size} bytes\n")
                    f.write(f"      Risk Score: {score}/10\n")
                    f.write(f"      --- EVIDENCE ---\n")
                    for ev in evidence:
                        f.write(f"      {ev}\n")
                    f.write("-" * 60 + "\n")
                    f.flush()

            except: pass
        
        if files_checked == 0:
            f.write("No files analyzed.\n")
        else:
            f.write(f"\nScan finished. Analyzed {files_checked} files in {(time.time() - start_time):.2f}s. Detections: {detections}.\n")
            
# --- FASE 26: STRING CLEANER & MEMORY MANIPULATION HUNTER ---
def fase_string_cleaning(palabras, modo):
    if cancelar_escaneo: return
    print("[26/26] String Cleaner & Memory Ops Hunter...")
    
    global reporte_cleaning
    base_path = HISTORIAL_RUTAS.get('path', os.path.abspath("."))
    folder_name = HISTORIAL_RUTAS.get('folder', "Resultados_SS")
    reporte_cleaning = os.path.join(base_path, folder_name, "String_Cleaner_Detection.txt")

    # Herramientas conocidas de manipulación de memoria
    cleaning_tools = [
        "processhacker", "kprocesshacker", "cheatengine", "dbk64", "ksdumper", 
        "pd-cleaner", "stringcleaner", "memreduct", "standbylist", "rammap", 
        "process explorer", "system informer"
    ]
    
    # Drivers de Kernel usados para limpiar memoria (R0)
    suspicious_drivers = ["kprocesshacker.sys", "dbk64.sys", "dbk32.sys", "procexp.sys", "rwdrv.sys"]

    with open(reporte_cleaning, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== MEMORY CLEANER & MANIPULATION SCAN: {datetime.datetime.now()} ===\n")
        f.write("Targets: Memory Editors, RAM Cleaners, Kernel RW Drivers.\n\n")

        # 1. BUSCAR PROCESOS ACTIVOS DE LIMPIEZA
        f.write("--- ACTIVE MEMORY TOOLS ---\n")
        try:
            cmd = 'tasklist /fo csv /nh'
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
            out, _ = proc.communicate()
            found_proc = False
            for line in out.splitlines():
                line_low = line.lower()
                if any(tool in line_low for tool in cleaning_tools):
                    f.write(f"[!!!] ACTIVE TOOL DETECTED: {line.split(',')[0].strip()}\n")
                    f.write("      (User is currently running a memory manipulator)\n")
                    found_proc = True
            if not found_proc: f.write("[OK] No memory cleaning tools running.\n")
        except: pass

        # 2. BUSCAR DRIVERS DE KERNEL CARGADOS (KProcessHacker es el más común para bypass)
        f.write("\n--- KERNEL DRIVER ARTIFACTS ---\n")
        try:
            cmd = 'driverquery /fo csv /nh'
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
            out, _ = proc.communicate()
            found_drv = False
            for line in out.splitlines():
                line_low = line.lower()
                if any(drv.replace(".sys","") in line_low for drv in suspicious_drivers):
                    f.write(f"[!!!] MEMORY RW DRIVER LOADED: {line.split(',')[0].strip()}\n")
                    f.write("      (Capabilities: Read/Write Kernel Memory - Anti-Anti-Cheat)\n")
                    found_drv = True
            if not found_drv: f.write("[OK] No standard cheating drivers found.\n")
        except: pass

        # 3. EVIDENCIA DE EJECUCIÓN PASADA (PREFETCH SPECÍFICO)
        f.write("\n--- EXECUTION HISTORY (PREFETCH) ---\n")
        try:
            # Usamos lógica simple de lectura directa para velocidad
            sysnative = r"C:\Windows\Sysnative\Prefetch"
            pf_path = sysnative if os.path.exists(sysnative) else r"C:\Windows\Prefetch"
            
            if os.path.exists(pf_path):
                found_pref = False
                with os.scandir(pf_path) as entries:
                    for entry in entries:
                        name = entry.name.lower()
                        if any(tool in name for tool in cleaning_tools):
                            f.write(f"[HISTORY] Tool previously run: {entry.name}\n")
                            found_pref = True
                if not found_pref: f.write("[OK] No history of cleaning tools.\n")
            else:
                f.write("[ERROR] Cannot access Prefetch (Admin rights needed).\n")
        except: pass
        
        # 4. DETECCION DE SERVICIOS (PERSISTENCIA)
        f.write("\n--- SUSPICIOUS SERVICES ---\n")
        try:
            # Buscamos servicios que contengan "Hacker" "Cheat" o "Kernel"
            cmd = 'sc query state= all'
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
            out, _ = proc.communicate()
            for line in out.splitlines():
                if "SERVICE_NAME" in line:
                    svc = line.split(":")[1].strip().lower()
                    if "kprocesshacker" in svc or "dbk" in svc or "faceit" in svc or "vanguard" in svc:
                        # Nota: Faceit/Vanguard no son cheats, pero son drivers de kernel interesantes de listar
                        tag = "[CHEAT ENGINE DRIVER]" if "dbk" in svc else "[INFO]"
                        if "kprocesshacker" in svc: tag = "[!!!] KPROCESS HACKER SERVICE"
                        f.write(f"{tag} Service found: {svc}\n")
        except: pass           
                 
# --- HTML REPORT ---
def generar_reporte_html(out_f, cfg):
    css = "<style>body{background-color:#090011;color:#f3e5f5;font-family:'Consolas',monospace;padding:20px}h1,h2{color:#d500f9;text-align:center;text-transform:uppercase;letter-spacing:2px;text-shadow:0 0 10px #d500f9}h3{color:#b388ff}a{color:#ea80fc;text-decoration:none;font-weight:bold;transition:0.3s}a:hover{color:#fff;text-shadow:0 0 8px #ea80fc}.card{border:1px solid #4a148c;background:#1a0526;margin:15px;padding:20px;border-left:5px solid #d500f9;box-shadow:0 0 15px rgba(74,20,140,0.4);transition:transform 0.2s}.card:hover{transform:scale(1.02);box-shadow:0 0 25px rgba(213,0,249,0.6)}pre{white-space:pre-wrap;word-wrap:break-word;background:#0f0018;padding:15px;border:1px solid #6a1b9a;color:#e1bee7;font-size:0.9em}.back-btn{display:inline-block;margin-bottom:20px;padding:10px 20px;border:1px solid #d500f9;color:#d500f9;border-radius:50px}.back-btn:hover{background:#d500f9;color:#090011}.footer{text-align:center;margin-top:50px;color:#7b1fa2;font-size:0.8em}.timestamp{color:#9c27b0;font-size:0.9em;text-align:center;margin-bottom:30px}</style>"
    fmap = {'f1':("ShimCache","Shimcache_Rastros.txt"), 'f2':("AppCompat","rastro_appcompat.txt"), 'f3':("Identity","cambios_sospechosos.txt"), 'f4':("Signatures","Digital_Signatures_ZeroTrust.txt"), 'f5':("Keywords","buscar_en_disco.txt"), 'f6':("Hidden","archivos_ocultos.txt"), 'f7':("MFT_ADS","MFT_Archivos.txt"), 'f8':("UserAssist","UserAssist_Decoded.txt"), 'f9':("USB","USB_History.txt"), 'f10':("DNS","DNS_Cache.txt"), 'f11':("Browser","Browser_Forensics.txt"), 'f12':("Persistence","Persistence_Check.txt"), 'f13':("Events","Windows_Events.txt"), 'f14':("ProcessHunter","Process_Hunter.txt"), 'f15':("GameCheats","Game_Cheat_Hunter.txt"), 'f16':("NuclearTraces","Nuclear_Traces.txt"), 'f17':("KernelHunter","Kernel_Anomalies.txt"), 'f18':("DNA_Prefetch","DNA_Prefetch.txt"), 'f19':("NetworkHunter","Network_Anomalies.txt"), 'f20':("ToxicLNK","Toxic_LNK.txt"), 'f21':("GhostTrails","Ghost_Trails.txt"), 'f22':("MemoryScanner","Memory_Injection_Report.txt"), 'f23':("RogueDrivers","Rogue_Drivers.txt"), 'f24':("DeepStatic","Deep_Static_Analysis.txt"), 'f25':("Metamorphosis","Metamorphosis_Report.txt"),'f26':("StringCleaner","String_Cleaner_Detection.txt"),'vt':("VirusTotal","detecciones_virustotal.txt")}
    g_l = []
    for k, (tit, arch) in fmap.items():
        if cfg.get(k,{}).get('active'):
            tp = os.path.join(out_f, arch)
            hf = f"{k}_{arch.replace('.txt','.html')}"; hp = os.path.join(out_f, hf); c_h = ""
            if os.path.exists(tp):
                try:
                    with open(tp,"r",encoding="utf-8",errors="replace") as f: rc = f.read(); rc = rc.replace("<", "&lt;").replace(">", "&gt;"); rc = rc.replace("[!!!]", "<span style='color:#ff1744; font-weight:bold; text-shadow: 0 0 5px #ff1744;'>[!!!]</span>"); c_h = f"<pre>{rc if rc.strip() else 'Clean.'}</pre>"
                except Exception as e: c_h = f"<p style='color:red'>Error: {e}</p>"
            else: c_h = "<p style='color:gray'>Pending...</p>"
            with open(hp,"w",encoding="utf-8") as f: f.write(f"<!DOCTYPE html><html><head><title>{tit}</title>{css}</head><body><a href='index.html' class='back-btn'>&lt; BACK</a><h1>{tit}</h1><div class='card'>{c_h}</div><div class='footer'>SCANNELER V80</div></body></html>")
            g_l.append((tit, hf))
    dbh = f"<!DOCTYPE html><html><head><title>DASHBOARD</title>{css}<meta http-equiv='refresh' content='5'></head><body><h1>SCANNELER <span style='color:#d500f9'>|</span> REPORT</h1><div class='timestamp'>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div><div style='display:flex;flex-wrap:wrap;justify-content:center;'>"
    if not g_l: dbh += "<p>No phases selected.</p>"
    else:
        for t, l in g_l: dbh += f"<div class='card' style='width:300px;text-align:center;'><h3>{t}</h3><p><a href='{l}'>VIEW REPORT &gt;</a></p></div>"
    dbh += "</div><div class='footer'>JELER33 PRIVATE TOOL</div></body></html>"
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
        
        opts = [("Fase 1: ShimCache Analysis", 'f1'), ("Fase 2: AppCompat Store", 'f2'), ("Fase 3: Identity Verification", 'f3'), ("Fase 4: Digital Signatures", 'f4'), ("Fase 5: Keyword Search", 'f5'), ("Fase 6: Hidden Files Scan", 'f6'), ("Fase 7: MFT & ADS Scan", 'f7'), ("Fase 8: UserAssist (ROT13)", 'f8'), ("Fase 9: USB Device History", 'f9'), ("Fase 10: Active DNS Cache", 'f10'), ("Fase 11: Browser Forensics", 'f11'), ("Fase 12: Persistence", 'f12'), ("Fase 13: Windows Event Logs", 'f13'), ("Fase 14: RAM Process Hunter", 'f14'), ("Fase 15: Game Cheat Hunter (Deep)", 'f15'), ("Fase 16: Nuclear Traces (BAM/Pipes)", 'f16'), ("Fase 17: Kernel Hunter (Drivers)", 'f17'), ("Fase 18: DNA & Prefetch (Forensic)", 'f18'), ("Fase 19: Network Deep Inspection", 'f19'), ("Fase 20: Toxic LNK & Module Hunter", 'f20'), ("Fase 21: Ghost Trails (Registry MRU)", 'f21'), ("Fase 22: Memory Injection Hunter (Elite)", 'f22'), ("Fase 23: Rogue Driver Hunter (Kernel)", 'f23'),("Fase 24: Deep Static Heuristics (Hidden Files)", 'f24'), ("Fase 25: Metamorphosis Hunter (Hot-Swap)", 'f25'), ("F26: String Cleaner", 'f26'),("Cloud: VirusTotal API", 'vt')]
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
        self.wid = self.canvas.create_window(450, 300, window=self.content, anchor="center") # Anchor center
        self.canvas.bind("<Configure>", lambda e: self.canvas.coords(self.wid, e.width/2, e.height/2)) # Auto-center on resize

        tk.Label(self.content, text=t("audit_prog"), font=("Consolas", 18, "bold"), bg=COLOR_BG, fg=COLOR_ACCENT).pack(pady=40)
        self.l_status = tk.Label(self.content, text=t("init"), font=("Consolas", 12), bg=COLOR_BG, fg=COLOR_TEXT); self.l_status.pack(pady=30)
        BotonDinamico(self.content, COLOR_DANGER, text=t("stop_scan"), command=self.stop, width=25).pack()
        
        self.scan_thread = threading.Thread(target=self.run_scan, daemon=True); self.scan_thread.start()
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
        global reporte_shim, reporte_appcompat, reporte_sospechosos, reporte_firmas, reporte_path, reporte_ocultos, reporte_mft, reporte_vt, reporte_userassist, reporte_usb, reporte_dns, reporte_browser, reporte_persistencia, reporte_eventos, reporte_process, reporte_game, reporte_nuclear, reporte_kernel, reporte_dna, reporte_network, reporte_toxic, reporte_ghost, reporte_memory, reporte_drivers, reporte_static, reporte_morph
        bd, fn = self.rutas.get('path', os.path.abspath(".")), self.rutas.get('folder', "Resultados_SS")
        fp = os.path.join(bd, fn)
        if not os.path.exists(fp): os.makedirs(fp, exist_ok=True)
        reporte_shim = os.path.join(fp, "Shimcache_Rastros.txt"); reporte_appcompat = os.path.join(fp, "rastro_appcompat.txt"); reporte_path = os.path.join(fp, "buscar_en_disco.txt"); reporte_sospechosos = os.path.join(fp, "cambios_sospechosos.txt"); reporte_firmas = os.path.join(fp, "Digital_Signatures_ZeroTrust.txt"); reporte_ocultos = os.path.join(fp, "archivos_ocultos.txt"); reporte_mft = os.path.join(fp, "MFT_Archivos.txt"); reporte_vt = os.path.join(fp, "detecciones_virustotal.txt"); reporte_userassist = os.path.join(fp, "UserAssist_Decoded.txt"); reporte_usb = os.path.join(fp, "USB_History.txt"); reporte_dns = os.path.join(fp, "DNS_Cache.txt"); reporte_browser = os.path.join(fp, "Browser_Forensics.txt"); reporte_persistencia = os.path.join(fp, "Persistence_Check.txt"); reporte_eventos = os.path.join(fp, "Windows_Events.txt"); reporte_process = os.path.join(fp, "Process_Hunter.txt"); reporte_game = os.path.join(fp, "Game_Cheat_Hunter.txt"); reporte_nuclear = os.path.join(fp, "Nuclear_Traces.txt"); reporte_kernel = os.path.join(fp, "Kernel_Anomalies.txt"); reporte_dna = os.path.join(fp, "DNA_Prefetch.txt"); reporte_network = os.path.join(fp, "Network_Anomalies.txt"); reporte_toxic = os.path.join(fp, "Toxic_LNK.txt"); reporte_ghost = os.path.join(fp, "Ghost_Trails.txt"); reporte_memory = os.path.join(fp, "Memory_Injection_Report.txt"); reporte_drivers = os.path.join(fp, "Rogue_Drivers.txt"); reporte_static = os.path.join(fp, "Deep_Static_Analysis.txt"); reporte_morph = os.path.join(fp, "Metamorphosis_Report.txt");
        try: generar_reporte_html(fp, self.config)
        except: pass
        vte = self.config.get('vt', {}).get('active', False)
        if vte: 
            with open(reporte_vt, "w", encoding="utf-8") as f: f.write(f"=== VT: {datetime.datetime.now()} ===\n\n")
            threading.Thread(target=worker_virustotal, daemon=True).start()
        
        fases = [('f1', fase_shimcache), ('f2', fase_rastro_appcompat), ('f3', fase_nombre_original), ('f4', fase_verificar_firmas), ('f5', fase_buscar_en_disco), ('f6', fase_archivos_ocultos), ('f7', fase_mft_ads), ('f8', fase_userassist), ('f9', fase_usb_history), ('f10', fase_dns_cache), ('f11', fase_browser_forensics), ('f12', fase_persistence), ('f13', fase_event_logs), ('f14', fase_process_hunter), ('f15', fase_game_cheat_hunter), ('f16', fase_nuclear_traces), ('f17', fase_kernel_hunter), ('f18', fase_dna_prefetch), ('f19', fase_network_hunter), ('f20', fase_toxic_lnk), ('f21', fase_ghost_trails), ('f22', fase_memory_anomaly), ('f23', fase_rogue_drivers), ('f24', fase_deep_static), ('f25', fase_metamorphosis_hunter), ('f26', fase_string_cleaning)]
        
        for k, func in fases:
            if cancelar_escaneo: break
            if self.config.get(k, {}).get('active'):
                self.update_status(f"Running: {k.upper()}...")
                
                # --- LOGICA CORREGIDA DE ARGUMENTOS ---
                args = []
                if k == 'f3': args = [vte, self.palabras, self.config[k]['modo']]
                elif k == 'f4': args = [self.palabras, vte, self.config[k]['modo']]
                elif k == 'f5': args = [self.palabras]
                elif k == 'f24': args = [self.palabras, self.config[k]['modo']] # F24 usa *args asi que esto funciona
                elif k == 'f25': args = [self.palabras, self.config[k]['modo']] # F25 tambien
                else: args = [self.palabras, self.config[k]['modo']]
                
                try: func(*args)
                except Exception as e: 
                    print(f"Error executing {k}: {e}") # Debug en consola
                
                # Actualizar HTML despues de cada fase para "Tiempo Real" visual
                try: generar_reporte_html(fp, self.config)
                except: pass
                
        cola_vt.put(None)
        if not cancelar_escaneo: 
            self.fp_final = fp; self.cola_estado.put("DONE_SIGNAL")

if __name__ == "__main__":
    if check_security():
        sys.exit()
    
    # --- INICIALIZAR YARA AQUÍ ---
    print("Cargando motor de detección...")
    inicializar_yara() 
    # -----------------------------
    
    app = ScannelerApp()
    app.mainloop()