# Entrega 2 - Hash e autenticação segura

**Disciplina:** Segurança da Informação - UNIT (Sistemas de Informação/ADS)
**Docente:** Ana Carla do Nascimento Santos
**Aluno:** Carlos Danilo Medeiros Cavalcante

## O que o projeto faz
Cadastro e login de usuários **sem guardar a senha em texto puro**. Só o hash (scrypt) e o sal ficam no banco SQLite.

## Como rodar
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python demo2.py                 # demonstração (mostra o banco e compara SHA-256 x scrypt)
python -m unittest -v testes    # 9 testes automatizados
```

## Arquivos
- `auth.py` - cadastro, login, geração e conferência do hash.
- `demo2.py` - demonstração com evidências.
- `testes.py` - testes automatizados (login certo/errado, usuário inexistente, SQL injection etc.).
- `evidencias_execucao.txt` e `evidencias_testes.txt` - saídas reais.

## Algoritmo e parâmetros
- **scrypt** (biblioteca `cryptography`): N=2^17, r=8, p=1 (128 MiB por hash), saída de 32 bytes.
- **Sal:** 16 bytes aleatórios (`os.urandom`), diferente para cada usuário.
- **Armazenamento:** `scrypt$N$r$p$sal$hash` (parâmetros junto do hash).
- **Senha:** 8 a 128 caracteres, normalizada em Unicode NFKC.
- **Comparação:** método `verify()` da biblioteca (tempo constante), sem usar `==`.

## Por que não SHA-256 sozinho?
É rápido demais (permite milhões de palpites por segundo), sem sal gera hashes iguais para senhas iguais e não tem custo ajustável nem usa memória.

## Limites
Sem limite de tentativas de login, sem pepper, sem verificação de senhas vazadas, sem HTTPS/recuperação de senha. Melhoria prevista: migrar para Argon2id.
