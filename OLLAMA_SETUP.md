# Use the Ghost Data investigator with local Ollama

This patch changes `code/agent.py` so it can use your local Ollama model instead of requiring OpenAI API credits. It does not change `code/main.py` or the batch `output.csv` generator.

## 1. Replace the agent file

Copy the `code/agent.py` from this ZIP into your existing project, replacing:

`hackerrank-orchestrate-october26\code\agent.py`

Keep your existing `dataset`, `code/main.py`, and evaluation files.

## 2. Confirm Ollama and Qwen are available

In PowerShell:

```powershell
ollama --version
ollama list
```

Make sure `qwen2.5:3b` appears in the model list. If it does not, run:

```powershell
ollama pull qwen2.5:3b
```

Ollama normally serves its local API at `http://localhost:11434`.

## 3. Check local tools first (no model call)

From the project root:

```powershell
python code/agent.py --case case_33 --dry-run
```

## 4. Run the local AI agent (no OpenAI key)

```powershell
python code/agent.py --provider ollama --model qwen2.5:3b --case case_33
```

If Ollama is hosted at a different URL, add `--base-url http://localhost:11434` with your actual local endpoint.

## Notes

- Ollama is the default provider, so `python code/agent.py --case case_33` also uses `qwen2.5:3b`.
- No `OPENAI_API_KEY` is needed for Ollama.
- The agent uses local tools for evidence search, activity search, identity history, and policy lookup. It is advisory and must not execute destructive actions.
- The agent's results are not automatically inserted into `output.csv`. The deterministic batch pipeline remains separate until a later, validated integration step.
- Qwen 2.5 3B is a small model; verify its evidence citations and conclusions rather than trusting unsupported claims.
