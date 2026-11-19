"""Demonstracao da Entrega 2: cadastro, login e por que SHA-256 sozinho nao serve."""
import os, time, hashlib, sqlite3
from auth import *

if os.path.exists("usuarios.db"):
    os.remove("usuarios.db")
con = conectar("usuarios.db")

print("=== 1. Cadastro de usuarios (senhas de teste) ===")
cadastrar(con, "carlos", "SenhaDeTeste#2026")
cadastrar(con, "ana", "SenhaDeTeste#2026")      # mesma senha de proposito
print("Usuarios 'carlos' e 'ana' cadastrados com a MESMA senha.")
for msg, u, s in [("senha curta (123)", "joao", "123"), ("usuario repetido", "carlos", "OutraSenha#99")]:
    try:
        cadastrar(con, u, s)
    except ErroCadastro as e:
        print(f"Cadastro recusado ({msg}): {e}")

print("\n=== 2. O que fica gravado no banco (evidencia de registro protegido) ===")
for uid, u, h, criado in con.execute("SELECT id, usuario, senha_hash, criado_em FROM usuarios"):
    alg, n, r, p, salt, hh = h.split("$")
    print(f"id={uid} usuario={u}")
    print(f"   algoritmo={alg} N={n} r={r} p={p}")
    print(f"   sal  ={salt}")
    print(f"   hash ={hh}")
print("A senha em texto puro NAO aparece em nenhum campo.")

print("\n=== 3. Testes de login ===")
print("carlos + senha correta   ->", login(con, "carlos", "SenhaDeTeste#2026"))
print("carlos + senha incorreta ->", login(con, "carlos", "senha-errada-123"))
print("usuario inexistente      ->", login(con, "fantasma", "SenhaDeTeste#2026"))
print("tentativa de SQL injection ->", login(con, "carlos' OR '1'='1", "x"))

print("\n=== 4. Por que SHA-256 isolado nao serve para senhas ===")
senha = b"SenhaDeTeste#2026"
print("SHA-256 sem sal, usuario 1:", hashlib.sha256(senha).hexdigest())
print("SHA-256 sem sal, usuario 2:", hashlib.sha256(senha).hexdigest(), "<- IGUAL")
t = time.perf_counter(); qtd = 200_000
for i in range(qtd):
    hashlib.sha256(senha + str(i).encode()).digest()
tempo_sha = time.perf_counter() - t
print(f"SHA-256: {qtd:,} tentativas em {tempo_sha:.2f} s (~{qtd/tempo_sha:,.0f} por segundo, em 1 nucleo)")
t = time.perf_counter(); gerar_hash("SenhaDeTeste#2026"); tempo_sc = time.perf_counter() - t
print(f"scrypt : 1 tentativa em {tempo_sc:.2f} s (~{1/tempo_sc:,.1f} por segundo, usando 128 MiB de memoria)")
print(f"Diferenca: o scrypt e cerca de {(qtd/tempo_sha)*tempo_sc:,.0f} vezes mais lento para quem ataca.")
con.close()
