from ollama import Client

client = Client(host="http://localhost:11434")

# Una tool de juguete, igual en estructura a las de tu agente
tools = [{
    "type": "function",
    "function": {
        "name": "probar_payload",
        "description": "Inserta un payload en un parametro de una URL y devuelve la respuesta.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "parametro": {"type": "string"},
                "payload": {"type": "string"},
            },
            "required": ["url", "parametro", "payload"],
        },
    },
}]

resp = client.chat(
    model="pentest-owasp",
    messages=[{
        "role": "user",
        "content": "Prueba una inyeccion SQL basica en el parametro 'id' "
                   "de http://localhost:3000/producto. Usa la herramienta disponible.",
    }],
    tools=tools,
)

msg = resp.message
print("¿Pidió herramientas?:", bool(msg.tool_calls))
if msg.tool_calls:
    for tc in msg.tool_calls:
        print("  ->", tc.function.name, dict(tc.function.arguments))
else:
    print("Contenido de texto:", msg.content)