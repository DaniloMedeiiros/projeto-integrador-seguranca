"""Testes automatizados da Entrega 2. Rodar: python -m unittest -v testes"""
import unittest
import sqlite3
from auth import *


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.con = conectar(":memory:")

    def test_cadastro_e_login_correto(self):
        cadastrar(self.con, "carlos", "SenhaForte#2026")
        self.assertTrue(login(self.con, "carlos", "SenhaForte#2026"))

    def test_login_senha_incorreta(self):
        cadastrar(self.con, "carlos", "SenhaForte#2026")
        self.assertFalse(login(self.con, "carlos", "senhaerrada1"))

    def test_login_usuario_inexistente(self):
        self.assertFalse(login(self.con, "fantasma", "qualquer-senha-1"))

    def test_banco_nao_guarda_senha_em_texto_puro(self):
        cadastrar(self.con, "ana", "MinhaSenha@123")
        linha = self.con.execute("SELECT * FROM usuarios").fetchone()
        self.assertNotIn("MinhaSenha@123", " ".join(str(c) for c in linha))
        self.assertTrue(linha[2].startswith("scrypt$"))

    def test_mesma_senha_gera_hashes_diferentes(self):
        cadastrar(self.con, "user1", "senhaIgual#1")
        cadastrar(self.con, "user2", "senhaIgual#1")
        h = [r[0] for r in self.con.execute("SELECT senha_hash FROM usuarios")]
        self.assertNotEqual(h[0], h[1])
        self.assertNotEqual(h[0].split("$")[4], h[1].split("$")[4])   # sais diferentes

    def test_senha_curta_rejeitada(self):
        with self.assertRaises(ErroCadastro):
            cadastrar(self.con, "joao", "123")

    def test_usuario_duplicado_rejeitado(self):
        cadastrar(self.con, "maria", "SenhaBoa#2026")
        with self.assertRaises(ErroCadastro):
            cadastrar(self.con, "maria", "OutraSenha#2026")

    def test_sql_injection_nao_funciona(self):
        cadastrar(self.con, "carlos", "SenhaForte#2026")
        self.assertFalse(login(self.con, "carlos' OR '1'='1", "qualquer-coisa"))

    def test_hash_adulterado_nao_confere(self):
        reg = gerar_hash("SenhaForte#2026")
        partes = reg.split("$"); partes[5] = b64(bytes(32))
        self.assertFalse(conferir_hash("SenhaForte#2026", "$".join(partes)))

if __name__ == "__main__":
    unittest.main(verbosity=2)
