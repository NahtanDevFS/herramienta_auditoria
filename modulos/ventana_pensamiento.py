# ventana_pensamiento.py - Ventana flotante (Tkinter) del hilo de pensamiento del agente
# Corre en un subproceso y lee eventos en tiempo real para mostrar razonamientos.
# Uso interno: lanzado por EmisorPensamiento.

import json
import os
import sys

ICONOS = {"pensando": "\U0001F914", "accion": "\u27A1\uFE0F", "resultado": "   \u2714",
          "hallazgo": "\U0001F6A8", "info": "\u2139\uFE0F"}


def _main_ventana(archivo):
    import tkinter as tk
    from tkinter import scrolledtext

    root = tk.Tk()
    root.title("Razonamiento del agente")
    # Quitamos la decoracion (barra de titulo/bordes) directamente desde Tk en vez
    # de depender de la regla de fluxbox (~/.fluxbox/apps), que no matchea de forma
    # fiable la clase de la ventana Tk. Asi la ventana ocupa exactamente su
    # geometria y no se sale de la pantalla.
    root.overrideredirect(True)
    # Posicion calculada desde el ancho REAL de la pantalla (no valores fijos), para
    # que la ventana quede pegada a la derecha pero SIEMPRE dentro del area visible,
    # con margen, sin desbordarse (aunque cambie la resolucion del escritorio).
    root.update_idletasks()
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    margen = 20
    ancho = 600
    alto = max(sh - 2 * margen, 400)
    x = max(sw - ancho - margen, 0)   # pegada a la derecha, con margen
    root.geometry(f"{ancho}x{alto}+{x}+{margen}")
    root.update_idletasks()
    root.configure(bg="#0d1117")

    tk.Label(root, text="Razonamiento del agente en vivo", bg="#0d1117",
             fg="#58a6ff", font=("Segoe UI", 15, "bold")).pack(pady=10)

    # wrap=CHAR asegura que URLs y payloads largos sin espacios (p.ej.
    # http://host.docker.internal:5173/admin) tambien se ajusten al ancho y no
    # se desborden horizontalmente.
    txt = scrolledtext.ScrolledText(root, bg="#0d1117", fg="#c9d1d9",
                                    font=("Consolas", 12), wrap=tk.CHAR,
                                    borderwidth=0, padx=10, pady=10)
    txt.pack(expand=True, fill="both", padx=(12, 16), pady=(0, 12))
    txt.tag_config("pensando", foreground="#d29922")
    txt.tag_config("accion", foreground="#58a6ff")
    txt.tag_config("resultado", foreground="#3fb950")
    txt.tag_config("hallazgo", foreground="#f85149", font=("Consolas", 12, "bold"))
    txt.tag_config("info", foreground="#8b949e")

    estado = {"pos": 0}

    def poll():
        try:
            if os.path.exists(archivo):
                with open(archivo, encoding="utf-8") as f:
                    f.seek(estado["pos"])
                    for linea in f:
                        linea = linea.strip()
                        if not linea:
                            continue
                        try:
                            ev = json.loads(linea)
                        except Exception:
                            continue
                        tipo = ev.get("tipo", "info")
                        texto = ev.get("texto", "")
                        if tipo == "fin":
                            root.title("Razonamiento del agente (finalizado)")
                            continue
                        icono = ICONOS.get(tipo, "")
                        txt.insert(tk.END, f"{icono} {texto}\n\n", tipo)
                        txt.see(tk.END)
                        txt.yview_moveto(1.0)
                    estado["pos"] = f.tell()
        except Exception:
            pass
        root.after(250, poll)

    poll()
    root.mainloop()


class EmisorPensamiento:
    # Lanza la ventana en un subproceso y le envia eventos escribiendo en un archivo.

    def __init__(self, activo=True, logger=None):
        self.activo = bool(activo)
        self.logger = logger
        self._f = None
        self._proc = None
        if not self.activo:
            return
        import subprocess
        import tempfile
        try:
            tmp = tempfile.NamedTemporaryFile(prefix="pensamiento_", suffix=".jsonl",
                                              delete=False)
            self._ruta = tmp.name
            tmp.close()
            self._f = open(self._ruta, "a", encoding="utf-8")
            self._proc = subprocess.Popen(
                [sys.executable, "-m", "modulos.ventana_pensamiento", self._ruta],
                cwd=os.getcwd(),
            )
            if logger:
                logger.info("[pensamiento] Ventana de razonamiento abierta.")
        except Exception as e:
            if logger:
                logger.warning(f"[pensamiento] No se pudo abrir la ventana: {e}")
            self.activo = False

    def emitir(self, tipo, texto):
        if not self.activo or not self._f:
            return
        try:
            self._f.write(json.dumps({"tipo": tipo, "texto": texto},
                                     ensure_ascii=False) + "\n")
            self._f.flush()
        except Exception:
            pass

    def cerrar(self):
        # Deja la ventana ABIERTA para lectura; el usuario la cierra al final.
        self.emitir("fin", "")
        try:
            if self._f:
                self._f.close()
        except Exception:
            pass


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        _main_ventana(sys.argv[1])
    else:
        print("uso: python -m modulos.ventana_pensamiento <archivo_eventos>",
              file=sys.stderr)
        sys.exit(2)