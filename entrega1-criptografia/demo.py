"""Demonstracao da Entrega 1: roda tudo e mostra sucesso e falha apos adulteracao."""
import copy
from cripto import *

SENHA = b"senha-de-teste-do-laboratorio"   # so para o laboratorio (nao e senha real)
MSG = "Pedido 4821: transferir R$ 100,00 para a conta de teste.".encode()

print("=== 1. Geracao de chaves ===")
priv_rsa, pub_rsa = gerar_chaves_rsa()
priv_ed, pub_ed = gerar_chaves_ed25519()
salvar_chaves(priv_rsa, pub_rsa, "rsa_destinatario", SENHA)
salvar_chaves(priv_ed, pub_ed, "ed25519_remetente", SENHA)
print("Par RSA-3072 (destinatario) e par Ed25519 (remetente) gerados em ./chaves")

print("\n=== 2. Cifragem hibrida (sigilo) ===")
print("Mensagem original :", MSG.decode())
pacote = cifrar(MSG, pub_rsa)
print("Conteudo cifrado  :", pacote["conteudo"][:60] + "...")
print("Chave AES cifrada :", pacote["chave_encapsulada"][:60] + "...")
print("Decifrado         :", decifrar(pacote, priv_rsa).decode())

print("\n=== 3. Teste de adulteracao do conteudo cifrado ===")
adulterado = copy.deepcopy(pacote)
raw = bytearray(unb64(adulterado["conteudo"]))
raw[0] ^= 0x01                       # troca 1 unico bit
adulterado["conteudo"] = b64(bytes(raw))
try:
    decifrar(adulterado, priv_rsa)
    print("FALHA NO TESTE: aceitou dado adulterado!")
except InvalidTag:
    print("Adulteracao DETECTADA (InvalidTag do AES-GCM). Decifragem recusada.")

print("\n=== 4. Assinatura digital (autenticidade) ===")
assinatura = assinar(MSG, priv_ed)
print("Assinatura (base64):", b64(assinatura)[:60] + "...")
print("Mensagem original  -> assinatura valida?", verificar(MSG, assinatura, pub_ed))
msg_alterada = MSG.replace(b"100,00", b"900,00")
print("Mensagem alterada  -> assinatura valida?", verificar(msg_alterada, assinatura, pub_ed))
outra_priv, outra_pub = gerar_chaves_ed25519()
print("Chave publica errada -> assinatura valida?", verificar(MSG, assinatura, outra_pub))

print("\n=== 5. Sigilo x autenticidade ===")
print("Cifrar sem assinar: so o destinatario le, mas ninguem prova QUEM mandou.")
print("Assinar sem cifrar: todos leem, mas todos conferem QUEM mandou e se mudou.")
print("Aqui usamos os dois: cifra (sigilo) + assina (autenticidade).")
