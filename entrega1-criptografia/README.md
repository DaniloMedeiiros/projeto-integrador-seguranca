# Entrega 1 - Criptografia assimétrica e confiança

**Disciplina:** Segurança da Informação - UNIT (Sistemas de Informação/ADS)
**Docente:** Ana Carla do Nascimento Santos
**Aluno:** Carlos Danilo Medeiros Cavalcante

## O que o projeto faz
Simula o envio de uma mensagem para outro serviço com:
1. **Sigilo** - cifragem híbrida: AES-256-GCM (conteúdo) + RSA-OAEP (protege a chave AES).
2. **Autenticidade** - assinatura digital com Ed25519.
3. **Testes de adulteração** - mostra o que acontece quando a mensagem ou o pacote é alterado.

## Como rodar
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python demo.py
```
A saída esperada está em `evidencias_execucao.txt`.

## Arquivos
- `cripto.py` - funções de gerar chaves, cifrar/decifrar, assinar/verificar.
- `demo.py` - demonstração com sucesso e falha após adulteração.
- `requirements.txt` - dependência (biblioteca `cryptography`).
- `evidencias_execucao.txt` - saída real da execução.

## Algoritmos e parâmetros
| Função | Algoritmo | Parâmetros |
|---|---|---|
| Conteúdo | AES-GCM | chave de 256 bits nova a cada mensagem, nonce de 96 bits aleatório |
| Encapsular a chave | RSA-OAEP | RSA de 3072 bits, expoente 65537, SHA-256 e MGF1-SHA-256 |
| Assinatura | Ed25519 | chave de 256 bits |

## Gestão de chaves
- A chave privada é salva em PEM/PKCS#8 **criptografada com senha**.
- A chave pública pode ser distribuída; a privada nunca deve ir para o repositório (veja `.gitignore`).
- A senha do `demo.py` é só de laboratório. Em um sistema real ela viria de um cofre de segredos.
- As chaves são geradas a cada execução, em `./chaves`.

## Limites da solução
- Não há certificado digital nem PKI: a chave pública do destinatário é "confiada" sem validação.
- A assinatura não tem data/hora, então não protege contra reenvio (replay).
- Não há rotação nem revogação de chaves.
- É um trabalho de estudo; foram usadas apenas bibliotecas consolidadas, sem algoritmo criptográfico próprio.
