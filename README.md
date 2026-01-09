# FileGuard — Monitor de Integridade de Ficheiros (HIDS simplificado)

Ferramenta em Python para monitorizar a integridade de ficheiros com baseline (SHA-256), deteção de alterações (novo/modificado/apagado), whitelist/blacklist e monitorização em tempo real.

## Funcionalidades
- Criação de baseline com hashes SHA-256
- Verificação de integridade (comparação com baseline)
- Monitorização em tempo real (`--watch`) via watchdog
- Whitelist/Blacklist via `config.json`
- Logging e geração de relatório HTML (`--report`)

## Requisitos
- Python 3.10+
- Linux (testado em Ubuntu 24.04)

## Instalação
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
