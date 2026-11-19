"""
Entrega 2 - Hash e autenticacao segura
Disciplina: Seguranca da Informacao (UNIT)
Aluno: Carlos Danilo Medeiros Cavalcante

Cadastro e login com scrypt (biblioteca 'cryptography'), usando sal aleatorio
por usuario. Nenhum algoritmo de hash foi implementado por mim.
Parametros seguem o minimo do OWASP para scrypt: N=2^17, r=8, p=1.
"""
import os
import re
import base64
import sqlite3
import unicodedata
from datetime import datetime, timezone
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey

N, R, P = 2**17, 8, 1        # custo de CPU/memoria (128 MiB por hash), bloco, paralelismo
SALT_BYTES = 16              # 128 bits de sal aleatorio
HASH_BYTES = 32              # 256 bits de saida
MIN_SENHA, MAX_SENHA = 8, 128

b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s)


class ErroCadastro(Exception):
    pass


def _normalizar(senha: str) -> bytes:
    # NFKC: o mesmo texto digitado em aparelhos diferentes gera os mesmos bytes
    return unicodedata.normalize("NFKC", senha).encode("utf-8")


def _kdf(salt: bytes, n=N, r=R, p=P) -> Scrypt:
    return Scrypt(salt=salt, length=HASH_BYTES, n=n, r=r, p=p)


def gerar_hash(senha: str) -> str:
    """Devolve 'scrypt$N$r$p$salt$hash' (os parametros ficam junto do hash)."""
    salt = os.urandom(SALT_BYTES)
    h = _kdf(salt).derive(_normalizar(senha))
    return f"scrypt${N}${R}${P}${b64(salt)}${b64(h)}"


def conferir_hash(senha: str, registro: str) -> bool:
    """Comparacao feita pela biblioteca (verify), que e em tempo constante."""
    _, n, r, p, salt, h = registro.split("$")
    try:
        _kdf(unb64(salt), int(n), int(r), int(p)).verify(_normalizar(senha), unb64(h))
        return True
    except InvalidKey:
        return False


# registro falso, usado para gastar o mesmo tempo quando o usuario nao existe
_FALSO = gerar_hash("senha-falsa-apenas-para-gastar-tempo")


# ---------------- banco de dados ----------------
def conectar(caminho="usuarios.db"):
    con = sqlite3.connect(caminho)
    con.execute("""CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario TEXT NOT NULL UNIQUE,
        senha_hash TEXT NOT NULL,
        criado_em TEXT NOT NULL)""")
    return con


def cadastrar(con, usuario: str, senha: str):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", usuario):
        raise ErroCadastro("Usuario invalido (3 a 30 letras, numeros, _ . -).")
    if not (MIN_SENHA <= len(senha) <= MAX_SENHA):
        raise ErroCadastro(f"A senha deve ter entre {MIN_SENHA} e {MAX_SENHA} caracteres.")
    try:
        con.execute("INSERT INTO usuarios (usuario, senha_hash, criado_em) VALUES (?, ?, ?)",
                    (usuario, gerar_hash(senha), datetime.now(timezone.utc).isoformat()))
        con.commit()
    except sqlite3.IntegrityError:
        raise ErroCadastro("Usuario ja cadastrado.")


def login(con, usuario: str, senha: str) -> bool:
    # consulta parametrizada (evita SQL injection)
    linha = con.execute("SELECT senha_hash FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
    if linha is None:
        conferir_hash(senha, _FALSO)   # gasta o mesmo tempo: nao revela se o usuario existe
        return False
    return conferir_hash(senha, linha[0])
