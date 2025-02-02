import secrets
import hashlib
import base64
import os

def teste_miller_rabin(numero, iteracoes=40):
    if numero <= 1:
        return False
    if numero in (2, 3):
        return True
    if numero % 2 == 0:
        return False

    # Escreve numero - 1 como fator_base * 2^expoente
    fator_base = numero - 1
    expoente = 0
    while fator_base % 2 == 0:
        fator_base //= 2
        expoente += 1

    # Função para realizar o teste com uma base
    def is_composite(base):
        valor_atual = pow(base, fator_base, numero)
        if valor_atual == 1 or valor_atual == numero - 1:
            return False
        for _ in range(expoente - 1):
            valor_atual = pow(valor_atual, 2, numero)
            if valor_atual == numero - 1:
                return False
        return True

    # Realiza os testes de Miller-Rabin
    for _ in range(iteracoes):
        base = secrets.randbelow(numero - 2) + 2  # Gera base aleatória no intervalo [2, numero - 2]
        if is_composite(base):
            return False

    return True

def gerar_primo(tamanho_bits):
    while True:
        candidato_primo = secrets.randbits(tamanho_bits)
        candidato_primo = (candidato_primo | (1 << (tamanho_bits - 1))) | 1
        if teste_miller_rabin(candidato_primo):
            return candidato_primo
        
def inverso_modular(numero, modulo):
    
    def algoritmo_euclides_estendido(numero, divisor):
        if numero == 0:
            return divisor, 0, 1
        mdc, coeficiente_anterior, coeficiente_atual = algoritmo_euclides_estendido(divisor % numero, numero)
        coeficiente_novo = coeficiente_atual - (divisor // numero) * coeficiente_anterior
        
        return mdc, coeficiente_novo, coeficiente_anterior

    mdc, inverso, _ = algoritmo_euclides_estendido(numero, modulo)
    if mdc != 1:
        raise ValueError(f"{numero} e {modulo} não são coprimos, portanto, o inverso modular não existe.")
    
    return inverso % modulo


def gerar_chaves(tamanho_bits):
    primo_p = gerar_primo(tamanho_bits)
    primo_q = gerar_primo(tamanho_bits)
    while primo_p == primo_q:
        primo_q = gerar_primo(tamanho_bits)

    modulo_n = primo_p * primo_q
    totiente_n = (primo_p - 1) * (primo_q - 1)

    expoente_e = 65537
    if inverso_modular(expoente_e, totiente_n) is None:
        raise ValueError("65537 não é coprimo com phi(n). Tente novamente.")

    chave_privada_d = inverso_modular(expoente_e, totiente_n)

    chave_publica = (modulo_n, expoente_e)
    chave_privada = (modulo_n, chave_privada_d)

    return chave_publica, chave_privada


def gerar_mascara(seed, tamanho_desejado, algoritmo_hash):
    contador = 0
    mascara_resultante = b""
    while len(mascara_resultante) < tamanho_desejado:
        contador_em_bytes = contador.to_bytes(4, byteorder="big")
        mascara_resultante += algoritmo_hash(seed + contador_em_bytes).digest()
        contador += 1

    return mascara_resultante[:tamanho_desejado]

def aplicar_oaep(mensagem, modulo_n, algoritmo_hash):
    tamanho_chave = (modulo_n.bit_length() + 7) // 8
    tamanho_hash = algoritmo_hash().digest_size

    if len(mensagem) > tamanho_chave - 2 * tamanho_hash - 2:
        raise ValueError("Mensagem muito longa para o tamanho da chave RSA.")

    # Preenchimento com zeros e separador
    preenchimento = b"\x00" * (tamanho_chave - len(mensagem) - 2 * tamanho_hash - 2)
    bloco_dados = algoritmo_hash(b"").digest() + preenchimento + b"\x01" + mensagem

    # Geração de seed criptograficamente seguro
    seed = secrets.token_bytes(tamanho_hash)

    # Aplicação da máscara no bloco de dados e no seed
    mascara_dados = gerar_mascara(seed, len(bloco_dados), algoritmo_hash)
    dados_mascarados = bytes(x ^ y for x, y in zip(bloco_dados, mascara_dados))

    mascara_seed = gerar_mascara(dados_mascarados, len(seed), algoritmo_hash)
    seed_mascarado = bytes(x ^ y for x, y in zip(seed, mascara_seed))

    return b"\x00" + seed_mascarado + dados_mascarados


def remover_oaep(mensagem_preenchida, modulo_n, algoritmo_hash):
    tamanho_chave = (modulo_n.bit_length() + 7) // 8
    tamanho_hash = algoritmo_hash().digest_size

    if len(mensagem_preenchida) != tamanho_chave:
        raise ValueError("Tamanho da mensagem preenchida incorreto.")

    # Separação do seed mascarado e do bloco de dados mascarado
    seed_mascarado = mensagem_preenchida[1:1 + tamanho_hash]
    dados_mascarados = mensagem_preenchida[1 + tamanho_hash:]

    # Remoção das máscaras
    mascara_seed = gerar_mascara(dados_mascarados, len(seed_mascarado), algoritmo_hash)
    seed = bytes(x ^ y for x, y in zip(seed_mascarado, mascara_seed))

    mascara_dados = gerar_mascara(seed, len(dados_mascarados), algoritmo_hash)
    bloco_dados = bytes(x ^ y for x, y in zip(dados_mascarados, mascara_dados))

    # Verificação do hash de integridade
    hash_esperado = algoritmo_hash(b"").digest()
    if bloco_dados[:tamanho_hash] != hash_esperado:
        raise ValueError("Erro na validação do preenchimento OAEP.")

    # Recuperação da mensagem original
    indice_separador = bloco_dados.find(b"\x01", tamanho_hash)
    if indice_separador == -1:
        raise ValueError("Erro no formato do preenchimento OAEP.")

    return bloco_dados[indice_separador + 1:]


def cifrar_com_rsa(mensagem, chave):
    modulo_n, expoente_e = chave
    algoritmo_hash = hashlib.sha3_256

    mensagem_preenchida = aplicar_oaep(mensagem, modulo_n, algoritmo_hash) #mensagem.encode()
    mensagem_inteiro = int.from_bytes(mensagem_preenchida, byteorder="big")
    if mensagem_inteiro >= modulo_n:
        raise ValueError("Mensagem maior que o módulo RSA.")

    cifra_inteiro = pow(mensagem_inteiro, expoente_e, modulo_n)
    
    return cifra_inteiro

def decifrar_com_rsa(cifra, chave):
    modulo_n, expoente_d = chave
    algoritmo_hash = hashlib.sha3_256

    mensagem_inteiro = pow(cifra, expoente_d, modulo_n)
    mensagem_preenchida = mensagem_inteiro.to_bytes((modulo_n.bit_length() + 7) // 8, byteorder="big")
    mensagem_original = remover_oaep(mensagem_preenchida, modulo_n, algoritmo_hash)

    return mensagem_original  #mensagem_original.decode()


#Função que assina uma mensagem
#Recebe como parametros uma mensagem (string) e a chave privada ((int), (int)) e retorna a assinatura no formato base64 (string)
def assinar(msg, c_privada):
    #Calcular Hash da mensagem em claro
    sha = hashlib.sha3_256()
    sha.update(msg.encode())
    hash = sha.digest()

    #Criptografar Hash com a chave privada 
    assinatura = cifrar_com_rsa(hash, c_privada)
    #Transforma Hash assinado para formato base64
    assinatura_b64 = base64.b64encode(assinatura.to_bytes(256, byteorder="big")).decode()
    
    return assinatura_b64


#Função que verifica uma assinatura
#Recebe como parametros uma mensagem (string), a aasinatura em formato Base64 (string) e a chave publica ((int), (int)) e retorna verdadeiro ou falso (bool)
def verificar_assinatura(msg, assinatura, c_publica):
    
    #Tranforma assinatura de Base64 para inteiro
    assinatura_int = int.from_bytes(base64.b64decode(assinatura.encode()), "big")
    
    #Decifra assinatura para obter o Hash da mensagem
    hash_decifrado = decifrar_com_rsa(assinatura_int, c_publica)

    #Calcula o Hash da mensagem
    sha = hashlib.sha3_256()
    sha.update(msg.encode())
    hash_calculado = sha.digest()

    #compara hash obtido a partir da decriptação com o hash obtido diretamente da mensagem e os comapara
    return hash_decifrado == hash_calculado

def main():
    while True:
        print("\nEscolha uma opção:")
        print("1 - Gerar chaves (-c)")
        print("2 - Assinar mensagem (-a)")
        print("3 - Verificar assinatura (-v)")
        print("4 - Sair")
        
        escolha = input("Opção: ")

        if escolha == "1":
            pk, sk = gerar_chaves(1024)
            with open("chave_publica.txt", "w") as fpk:
                fpk.write(f"{hex(pk[0])}\n{hex(pk[1])}\n")
            with open("chave_privada.txt", "w") as fsk:
                fsk.write(f"{hex(sk[0])}\n{hex(sk[1])}")
            print("Chaves geradas com sucesso!")

        elif escolha == "2":
            mensagem = input("Digite o caminho do arquivo da mensagem: ")
            if os.path.exists(mensagem):
                with open(mensagem, "r") as msg:
                    mensagem = msg.read()

            chave_privada = input("Digite o caminho do arquivo da chave privada: ")
            if os.path.exists(chave_privada):
                with open(chave_privada, "r") as fsk:
                    tmp = fsk.readlines()
                    chave_privada = (int(tmp[0], 0), int(tmp[1], 0))

            with open("assinatura.txt", "w") as signature:
                signature.write(assinar(mensagem, chave_privada))
            print("Mensagem assinada com sucesso!")

        elif escolha == "3":
            mensagem = input("Digite o caminho do arquivo da mensagem: ")
            if os.path.exists(mensagem):
                with open(mensagem, "r") as msg:
                    mensagem = msg.read()

            chave_publica = input("Digite o caminho do arquivo da chave pública: ")
            if os.path.exists(chave_publica):
                with open(chave_publica, "r") as fpk:
                    tmp = fpk.readlines()
                    chave_publica = (int(tmp[0], 0), int(tmp[1], 0))

            assinatura = input("Digite o caminho do arquivo da assinatura: ")
            if os.path.exists(assinatura):
                with open(assinatura, "r") as signature:
                    assinatura = signature.read()

            resultado = verificar_assinatura(mensagem, assinatura, chave_publica)
            print(f"Assinatura válida? {resultado}")

        elif escolha == "4":
            print("Saindo...")
            break

        else:
            print("Opção inválida! Tente novamente.")

if __name__ == "__main__":
    main()
