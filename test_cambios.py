# Test unitario para las funciones modificadas en agente_pentesting py
# Verifica:
# _construir_objetivos: modo normal vs autenticado
# _seleccionar_endpoints_api: inyeccion de endpoints privados autenticados
# _firma_hallazgo: deduplicacion
# Heuristica A01: solo endpoints sensibles
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modulos.agente_pentesting import (
    _construir_objetivos, _seleccionar_endpoints_api, _firma_hallazgo,
    _PALABRAS_SENSIBLES_A01, _ENDPOINTS_PRIVADOS_CONOCIDOS,
)

# 1 _construir_objetivos: modo normal
mapa = [
    {"url": "http://localhost:3000/#/login", "tiene_login": True,
     "tiene_busqueda": False, "tiene_formulario": False, "tiene_parametros": False},
    {"url": "http://localhost:3000/#/search", "tiene_login": False,
     "tiene_busqueda": True, "tiene_formulario": False, "tiene_parametros": False},
    {"url": "http://localhost:3000/#/contact", "tiene_login": False,
     "tiene_busqueda": False, "tiene_formulario": True, "tiene_parametros": False},
]
rutas = ["http://localhost:3000/#/login", "http://localhost:3000/#/search",
         "http://localhost:3000/#/contact", "http://localhost:3000/#/register"]

objs_normal = _construir_objetivos(mapa, rutas)
tipos_normal = {o["tipo"] for o in objs_normal}
assert "login_bypass" in tipos_normal, f"Normal debe incluir login_bypass, tiene: {tipos_normal}"
assert "inyeccion_busqueda" in tipos_normal
assert "inyeccion_formulario" in tipos_normal
print(f"[OK] _construir_objetivos normal: {len(objs_normal)} objetivo(s), tipos: {tipos_normal}")

# 2 _construir_objetivos: modo autenticado (NO debe sembrar login)
objs_auth = _construir_objetivos(mapa, rutas, autenticado=True,
                                  url_objetivo="http://localhost:3000")
tipos_auth = {o["tipo"] for o in objs_auth}
assert "login_bypass" not in tipos_auth, \
    f"Autenticado NO debe incluir login_bypass, tiene: {tipos_auth}"
assert "inyeccion_busqueda" in tipos_auth
print(f"[OK] _construir_objetivos autenticado: {len(objs_auth)} objetivo(s), tipos: {tipos_auth}")

# 3 _seleccionar_endpoints_api: modo no autenticado (solo los del crawler)
eps_crawler = ["http://localhost:3000/api/Products", "http://localhost:3000/rest/admin/application-version"]
eps_normal = _seleccionar_endpoints_api(eps_crawler, autenticado=False)
assert len(eps_normal) == 2, f"Normal debe tener 2 endpoints, tiene {len(eps_normal)}"
print(f"[OK] _seleccionar_endpoints_api normal: {len(eps_normal)} endpoint(s)")

# 4 _seleccionar_endpoints_api: modo autenticado (inyecta privados)
eps_auth = _seleccionar_endpoints_api(
    eps_crawler, autenticado=True, url_objetivo="http://localhost:3000")
assert len(eps_auth) > len(eps_normal), \
    f"Autenticado debe tener MAS endpoints ({len(eps_auth)} vs {len(eps_normal)})"
# Verificar que se inyectaron endpoints privados conocidos
rutas_auth = [e.split("localhost:3000")[1] for e in eps_auth if "localhost:3000" in e]
tiene_basket = any("/rest/basket" in r for r in rutas_auth)
tiene_users = any("/api/Users" in r for r in rutas_auth)
assert tiene_basket or tiene_users, f"Debe inyectar endpoints privados, tiene: {rutas_auth}"
print(f"[OK] _seleccionar_endpoints_api autenticado: {len(eps_auth)} endpoint(s), "
      f"basket={tiene_basket}, users={tiene_users}")

# 5 _firma_hallazgo: deduplicacion
assert _firma_hallazgo("Bypass de login por SQLi", "A05") == "A05:bypass_auth"
assert _firma_hallazgo("XSS reflejado en busqueda", "A05") == "A05:xss_reflejado"
assert _firma_hallazgo("Inyeccion SQL en API", "A05") == "A05:sqli"
assert _firma_hallazgo("Bypass autenticacion", "A01") == "A05:bypass_auth"  # detecta por titulo
print("[OK] _firma_hallazgo: firmas correctas")

# 6 Palabras sensibles A01: validar que estan definidas
assert "user" in _PALABRAS_SENSIBLES_A01
assert "basket" in _PALABRAS_SENSIBLES_A01
assert "admin" in _PALABRAS_SENSIBLES_A01
assert len(_PALABRAS_SENSIBLES_A01) >= 10
print(f"[OK] _PALABRAS_SENSIBLES_A01: {len(_PALABRAS_SENSIBLES_A01)} palabras")

# 7 Endpoints privados conocidos
assert len(_ENDPOINTS_PRIVADOS_CONOCIDOS) >= 8
assert any("basket" in e for e in _ENDPOINTS_PRIVADOS_CONOCIDOS)
assert any("Users" in e for e in _ENDPOINTS_PRIVADOS_CONOCIDOS)
print(f"[OK] _ENDPOINTS_PRIVADOS_CONOCIDOS: {len(_ENDPOINTS_PRIVADOS_CONOCIDOS)} patron(es)")

print("\n=== TODOS LOS TESTS PASARON ===")
