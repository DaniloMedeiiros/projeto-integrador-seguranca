# Projeto Integrador - Segurança Aplicada ao Desenvolvimento

**Universidade Tiradentes (UNIT)** - Sistemas de Informação/ADS
**Disciplina:** Segurança da Informação
**Docente:** Ana Carla do Nascimento Santos
**Aluno:** Carlos Danilo Medeiros Cavalcante

Projeto com quatro entregas semanais. Cada pasta tem o código, um README próprio e as evidências de execução.

| Entrega | Tema | Pasta | Status |
|---|---|---|---|
| 1 | Criptografia assimétrica e confiança (AES-GCM + RSA-OAEP e assinatura Ed25519) | `entrega1-criptografia/` | Concluída |
| 2 | Hash e autenticação segura (cadastro/login com scrypt) | `entrega2-hash-autenticacao/` | Concluída |
| 3 | Varredura de portas e serviços (Nmap) | - | A fazer |
| 4 | Auditoria e correção de vulnerabilidades | - | A fazer |

## Como rodar
Requer Python 3 e a biblioteca `cryptography` (única dependência; nenhum algoritmo criptográfico foi implementado por conta própria).
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

cd entrega1-criptografia && python demo.py && cd ..
cd entrega2-hash-autenticacao && python demo2.py && python -m unittest -v testes
```
