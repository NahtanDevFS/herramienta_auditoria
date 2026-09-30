# Benchmark del agente

Mide la **precision de tool-calling** del modelo: dado el estado de una pagina,
comprueba si el agente llama a la herramienta correcta (y con los argumentos
esperados). Es la capacidad que de verdad define si el agente se comporta como
agente en vez de ponerse a escribir prosa.

## Que mide

- **Precision de tool-calling:** porcentaje de casos en los que el modelo elige
  la herramienta correcta (`probar_login`, `probar_busqueda`, `probar_idor`, etc.).
- **Aciertos con argumentos correctos:** ademas de la herramienta, que los
  argumentos clave contengan lo esperado (por ejemplo, un payload SQLi sin
  comillas escapadas).

Los casos estan en `casos.jsonl` (uno por linea). Anade los tuyos con el mismo
formato: `situacion`, `tool_esperada` y, opcional, `args_contienen`.

## Como ejecutarlo

Desde la raiz del proyecto.

Modelo en la nube (endpoint compatible con OpenAI):

```bash
LLM_BASE_URL=https://TU-ENDPOINT/v1 LLM_API_KEY=TU_CLAVE python3 -m benchmark.run_benchmark --proveedor openai --modelo pentest-owasp
```

Modelo local con Ollama:

```bash
python3 -m benchmark.run_benchmark --proveedor ollama --modelo jonathanFS/pentest-owasp
```

## Salida

Una tabla por caso (acierto/fallo de herramienta y de argumentos) y un resumen
con los dos porcentajes. El detalle se guarda en `benchmark/resultados_<fecha>.json`,
util para comparar el modelo antes y despues de reentrenar.
