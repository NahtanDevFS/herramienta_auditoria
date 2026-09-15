import logging
from modulos.crawler import ejecutar

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
cfg = {
    "objetivo": {"url": "http://localhost:3000/"},
    "crawler": {"max_paginas": 20, "render_js": True},
    "salida": {"carpeta": "resultados"},
}
hallazgos = ejecutar(cfg, logging.getLogger("test"))
print("\n=== MAPA DEL SITIO ===")
for e in cfg.get("_mapa_sitio", []):
    print(" ", e)