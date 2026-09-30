# Benchmark simple del agente de pentesting.
#
# Mide la capacidad que de verdad importa en un agente con herramientas: la
# PRECISION DE TOOL-CALLING. Para cada caso se le describe al modelo el estado de
# una pagina y se comprueba si llama a la herramienta CORRECTA (y, cuando aplica,
# con los argumentos esperados). Es la capacidad que estaba fallando (el modelo
# se ponia a escribir prosa en vez de pedir herramientas), asi que este numero
# resume si el agente se comporta como agente.
#
# No necesita el navegador ni un objetivo real: solo el endpoint del modelo. Se
# apoya en la misma capa cliente_llm que usa el agente, asi que mide el modelo
# tal y como corre en produccion (mismo muestreo, mismo tool_choice).
#
# Uso (desde la raiz del proyecto):
#   Nube:   LLM_BASE_URL=https://TU-ENDPOINT/v1 LLM_API_KEY=TU_CLAVE \
#           python3 -m benchmark.run_benchmark --proveedor openai --modelo pentest-owasp
#   Local:  python3 -m benchmark.run_benchmark --proveedor ollama --modelo jonathanFS/pentest-owasp
#
# Salida: una tabla por caso (acierto/fallo) y un resumen con la precision.
# Guarda el detalle en benchmark/resultados_<fecha>.json.

import argparse
import json
import os
from datetime import datetime

from modulos.cliente_llm import crear_cliente

RUTA_CASOS = os.path.join(os.path.dirname(__file__), "casos.jsonl")

INSTRUCCION_SISTEMA = (
    "Eres un agente de pentesting que audita un sitio web AUTORIZADO usando un "
    "navegador real. Ante cada situacion, DEBES responder llamando a la herramienta "
    "mas adecuada mediante tool calling (no escribas texto). Herramientas: "
    "navegar (ir a una URL), analizar_pagina (inspeccionar la pagina actual), "
    "probar_login (bypass de autenticacion en un formulario de login), "
    "probar_busqueda (inyeccion/XSS en un buscador), probar_formulario "
    "(inyeccion/XSS en un formulario de contacto/feedback), probar_idor "
    "(control de acceso roto en una URL con id). Usa los payloads clasicos sin "
    "escapar las comillas."
)

# Esquema de herramientas identico en espiritu al del agente con navegador.
TOOLS = [
    {"type": "function", "function": {
        "name": "navegar",
        "description": "Navega el navegador a una URL dentro del dominio autorizado.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "analizar_pagina",
        "description": "Inspecciona la pagina actual (formularios, buscador, enlaces).",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "probar_login",
        "description": "Prueba un bypass de autenticacion inyectando un payload en el login.",
        "parameters": {"type": "object", "properties": {
            "usuario": {"type": "string"}, "contrasena": {"type": "string"}},
            "required": ["usuario"]}}},
    {"type": "function", "function": {
        "name": "probar_busqueda",
        "description": "Inyecta un payload en el campo de busqueda (SQLi/XSS).",
        "parameters": {"type": "object", "properties": {
            "payload": {"type": "string"}}, "required": ["payload"]}}},
    {"type": "function", "function": {
        "name": "probar_formulario",
        "description": "Inyecta un payload en un formulario de contacto/feedback.",
        "parameters": {"type": "object", "properties": {
            "payload": {"type": "string"}}, "required": ["payload"]}}},
    {"type": "function", "function": {
        "name": "probar_idor",
        "description": "Prueba control de acceso roto (IDOR) variando el id de una URL.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"}}, "required": ["url"]}}},
]


def _cargar_casos(ruta):
    casos = []
    with open(ruta, encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if linea:
                casos.append(json.loads(linea))
    return casos


def _args_ok(esperado: dict, reales: dict) -> bool:
    # cada substring esperado debe aparecer (case-insensitive) en el arg real
    for clave, sub in (esperado or {}).items():
        valor = str((reales or {}).get(clave, "")).lower()
        if str(sub).lower() not in valor:
            return False
    return True


def evaluar(client, modelo, casos):
    filas = []
    for caso in casos:
        mensajes = [
            {"role": "system", "content": INSTRUCCION_SISTEMA},
            {"role": "user", "content": caso["situacion"]},
        ]
        tool_llamada, args_llamada, error = None, {}, None
        try:
            resp = client.chat(model=modelo, messages=mensajes, tools=TOOLS,
                               options={"temperature": 0.1})
            tcs = resp.message.tool_calls
            if tcs:
                tool_llamada = tcs[0].function.name
                args_llamada = tcs[0].function.arguments or {}
        except Exception as e:
            error = str(e)

        tool_ok = (tool_llamada == caso["tool_esperada"])
        args_ok = tool_ok and _args_ok(caso.get("args_contienen"), args_llamada)
        filas.append({
            "id": caso["id"],
            "esperada": caso["tool_esperada"],
            "obtenida": tool_llamada or (f"ERROR: {error}" if error else "(sin tool)"),
            "tool_ok": tool_ok,
            "args_ok": args_ok,
            "args": args_llamada,
        })
    return filas


def _imprimir(filas):
    print("\n" + "=" * 74)
    print(f"{'CASO':<20}{'ESPERADA':<20}{'OBTENIDA':<20}{'TOOL':<6}{'ARGS'}")
    print("-" * 74)
    for f in filas:
        print(f"{f['id']:<20}{f['esperada']:<20}{str(f['obtenida'])[:19]:<20}"
              f"{'OK' if f['tool_ok'] else 'X':<6}{'OK' if f['args_ok'] else '-'}")
    print("-" * 74)
    n = len(filas)
    tool_aciertos = sum(1 for f in filas if f["tool_ok"])
    args_aciertos = sum(1 for f in filas if f["args_ok"])
    con_args = sum(1 for f in filas if f.get("args"))  # informativo
    print(f"Precision de tool-calling: {tool_aciertos}/{n} = "
          f"{100 * tool_aciertos / n:.1f}%")
    print(f"Aciertos con argumentos correctos: {args_aciertos}/{n} = "
          f"{100 * args_aciertos / n:.1f}%")
    print("=" * 74 + "\n")
    return {"total": n, "tool_aciertos": tool_aciertos,
            "args_aciertos": args_aciertos,
            "precision_tool": round(100 * tool_aciertos / n, 1),
            "precision_args": round(100 * args_aciertos / n, 1)}


def main():
    ap = argparse.ArgumentParser(description="Benchmark de tool-calling del agente.")
    ap.add_argument("--proveedor", default=os.environ.get("LLM_PROVEEDOR", "openai"),
                    help="openai (nube) u ollama (local).")
    ap.add_argument("--modelo", default=os.environ.get("LLM_MODELO", "pentest-owasp"))
    ap.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", ""))
    ap.add_argument("--api-key", default=os.environ.get("LLM_API_KEY", "sk-no-key"))
    ap.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    args = ap.parse_args()

    cfg = {"proveedor": args.proveedor, "base_url": args.base_url,
           "api_key": args.api_key, "host": args.host}
    client = crear_cliente(cfg)

    casos = _cargar_casos(RUTA_CASOS)
    print(f"Ejecutando {len(casos)} caso(s) contra el modelo '{args.modelo}' "
          f"(proveedor: {args.proveedor})...")
    filas = evaluar(client, args.modelo, casos)
    resumen = _imprimir(filas)

    marca = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    salida = os.path.join(os.path.dirname(__file__), f"resultados_{marca}.json")
    with open(salida, "w", encoding="utf-8") as f:
        json.dump({"modelo": args.modelo, "proveedor": args.proveedor,
                   "resumen": resumen, "detalle": filas},
                  f, ensure_ascii=False, indent=2)
    print(f"Detalle guardado en {salida}")


if __name__ == "__main__":
    main()
