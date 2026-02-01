# FileGuard — Monitor de Integridade de Ficheiros (HIDS simplificado)

Ferramenta em Python para monitorizar a integridade de ficheiros através de baseline (SHA-256), deteção de alterações
(novo/modificado/apagado), whitelist/blacklist e monitorização em tempo real.

## Requisitos
- Python 3.10+
- Linux (testado em Ubuntu 24.04)

## Instalação
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
