# cliente_llm.py - Capa de cliente LLM unificada.
# Permite que el agente hable IGUAL con dos backends:
#   - "ollama": modelo local via Ollama (comportamiento original).
#   - "openai": cualquier endpoint compatible con la API de OpenAI (vLLM en Modal,
#               Together, Groq, etc.). Es como se sirve el fine-tune en la nube.
#
# La interfaz que expone es la MISMA que la de Ollama, para no reescribir el agente:
#   cliente.chat(model, messages, tools=None, options=None)
#       -> objeto con .message.content y
#          .message.tool_calls[i].function.name / .function.arguments (dict)

import json


def crear_cliente(cfg: dict, logger=None):
    # Fabrica el cliente segun 'proveedor' de la config del agente.
    proveedor = (cfg.get("proveedor") or "ollama").lower()
    if proveedor in ("openai", "openai_compat", "nube", "cloud", "vllm"):
        base_url = (cfg.get("base_url") or "").strip()
        api_key = cfg.get("api_key") or "sk-no-key"
        if not base_url:
            raise ValueError("Falta 'base_url' para el proveedor OpenAI-compatible "
                             "(por ejemplo https://...modal.run/v1).")
        if logger:
            logger.info(f"[agente_ia] Cliente LLM en modo NUBE (OpenAI-compatible): {base_url}")
        return _ClienteOpenAI(base_url, api_key, logger)
    # Por defecto: Ollama local (interfaz nativa, no necesita adaptador).
    from ollama import Client
    host = cfg.get("host") or "http://localhost:11434"
    if logger:
        logger.info(f"[agente_ia] Cliente LLM en modo LOCAL (Ollama): {host}")
    return Client(host=host)


# ---- Objetos de respuesta con la MISMA forma que los de Ollama ----
class _Funcion:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments   # siempre dict


class _LlamadaHerramienta:
    def __init__(self, name, arguments):
        self.function = _Funcion(name, arguments)


class _Mensaje:
    def __init__(self, content, tool_calls=None, role="assistant"):
        self.role = role
        self.content = content
        self.tool_calls = tool_calls or None


class _Respuesta:
    def __init__(self, message):
        self.message = message


def _leer(obj, clave, defecto=None):
    # Lee de un dict o de un atributo, indistintamente.
    if isinstance(obj, dict):
        return obj.get(clave, defecto)
    return getattr(obj, clave, defecto)


def _a_formato_openai(messages):
    # Traduce la lista de mensajes del agente (dicts de system/user, objetos de
    # respuesta del asistente, y tool-results con 'tool_name') al formato que exige
    # la API de OpenAI, emparejando cada tool-result con su tool_call_id.
    salida = []
    pendientes = []  # [(id, name)] de los tool_calls del ultimo assistant sin responder
    for m in messages:
        role = _leer(m, "role")
        if role == "tool":
            nombre = _leer(m, "tool_name") or _leer(m, "name")
            contenido = _leer(m, "content")
            if not isinstance(contenido, str):
                contenido = json.dumps(contenido, ensure_ascii=False, default=str)
            tcid = None
            for i, (cid, cname) in enumerate(pendientes):
                if cname == nombre:
                    tcid = cid
                    pendientes.pop(i)
                    break
            if tcid is None and pendientes:
                tcid, _ = pendientes.pop(0)
            salida.append({"role": "tool", "tool_call_id": tcid or "call_0",
                           "content": contenido})
        elif role == "assistant":
            contenido = _leer(m, "content") or ""
            tcs = _leer(m, "tool_calls")
            if tcs:
                oai_tcs = []
                pendientes = []
                for j, tc in enumerate(tcs):
                    fn = _leer(tc, "function")
                    nombre = _leer(fn, "name")
                    args = _leer(fn, "arguments")
                    if isinstance(args, (dict, list)):
                        args = json.dumps(args, ensure_ascii=False)
                    elif args is None:
                        args = "{}"
                    cid = f"call_{j}_{nombre}"
                    oai_tcs.append({"id": cid, "type": "function",
                                    "function": {"name": nombre, "arguments": args}})
                    pendientes.append((cid, nombre))
                salida.append({"role": "assistant", "content": contenido or None,
                               "tool_calls": oai_tcs})
            else:
                salida.append({"role": "assistant", "content": contenido})
        else:
            salida.append({"role": role, "content": _leer(m, "content")})
    return salida


class _ClienteOpenAI:
    # Adaptador que expone la interfaz de Ollama sobre un endpoint OpenAI-compatible.

    def __init__(self, base_url, api_key, logger=None):
        from openai import OpenAI
        self._cli = OpenAI(base_url=base_url, api_key=api_key, timeout=180)
        self._logger = logger

    def chat(self, model=None, messages=None, tools=None, options=None, **_):
        kwargs = {"model": model, "messages": _a_formato_openai(messages or [])}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        opts = options or {}
        if "temperature" in opts:
            kwargs["temperature"] = opts["temperature"]
        if "top_p" in opts:
            kwargs["top_p"] = opts["top_p"]
        # Qwen3: desactivar el modo "thinking" para el agente (no ensucia el contexto
        # ni interfiere con el tool-calling). vLLM lo acepta via chat_template_kwargs.
        kwargs["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}

        resp = self._cli.chat.completions.create(**kwargs)
        m = resp.choices[0].message

        tool_calls = None
        if getattr(m, "tool_calls", None):
            tool_calls = []
            for tc in m.tool_calls:
                args = tc.function.arguments
                try:
                    args = json.loads(args) if isinstance(args, str) else (args or {})
                except (ValueError, TypeError):
                    args = {}
                tool_calls.append(_LlamadaHerramienta(tc.function.name, args))
        return _Respuesta(_Mensaje(content=m.content or "", tool_calls=tool_calls))
