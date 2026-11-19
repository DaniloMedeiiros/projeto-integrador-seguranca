"""
Entrega 1 - Criptografia assimetrica e confianca
Disciplina: Seguranca da Informacao (UNIT)
Aluno: Carlos Danilo Medeiros Cavalcante

Usa a biblioteca 'cryptography' (nao implementei nenhum algoritmo por conta propria).
  - Cifragem hibrida: AES-256-GCM (conteudo) + RSA-OAEP/SHA-256 (encapsula a chave AES)
  - Assinatura digital: Ed25519
"""
import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import InvalidTag

b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s)

OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)


# ---------- geracao de chaves ----------
def gerar_chaves_rsa():
    privada = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return privada, privada.public_key()

def gerar_chaves_ed25519():
    privada = ed25519.Ed25519PrivateKey.generate()
    return privada, privada.public_key()

def salvar_chaves(privada, publica, nome, senha: bytes):
    """Chave privada vai criptografada com senha (PEM/PKCS8); publica em PEM."""
    os.makedirs("chaves", exist_ok=True)
    with open(f"chaves/{nome}_privada.pem", "wb") as f:
        f.write(privada.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(senha)))
    with open(f"chaves/{nome}_publica.pem", "wb") as f:
        f.write(publica.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))


# ---------- cifragem hibrida ----------
def cifrar(mensagem: bytes, chave_publica_rsa) -> dict:
    chave_aes = AESGCM.generate_key(bit_length=256)   # chave de sessao
    nonce = os.urandom(12)                            # nunca repetir com a mesma chave
    conteudo = AESGCM(chave_aes).encrypt(nonce, mensagem, None)
    chave_encapsulada = chave_publica_rsa.encrypt(chave_aes, OAEP)
    return {"chave_encapsulada": b64(chave_encapsulada),
            "nonce": b64(nonce),
            "conteudo": b64(conteudo)}   # inclui o tag de autenticacao GCM no final

def decifrar(pacote: dict, chave_privada_rsa) -> bytes:
    chave_aes = chave_privada_rsa.decrypt(unb64(pacote["chave_encapsulada"]), OAEP)
    return AESGCM(chave_aes).decrypt(unb64(pacote["nonce"]),
                                     unb64(pacote["conteudo"]), None)


# ---------- assinatura digital ----------
def assinar(mensagem: bytes, chave_privada_ed) -> bytes:
    return chave_privada_ed.sign(mensagem)

def verificar(mensagem: bytes, assinatura: bytes, chave_publica_ed) -> bool:
    try:
        chave_publica_ed.verify(assinatura, mensagem)
        return True
    except InvalidSignature:
        return False
