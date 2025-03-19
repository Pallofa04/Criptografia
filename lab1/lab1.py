import numpy as np

# Funció per convertir text a llista de valors hexadecimals
def text_to_hex(text):
    """Converteix un text a llista de valors hexadecimals"""
    return [hex(ord(c)) for c in text]

## Exercici 1 - Pots escollir quin text utilitzar
text_original = "Arnau Pol"
nom_xifrat = ['32', '43', 'f6', 'a8', '88', '5a', '30', '8d', '31', '31', '98', 'a2', 'e0', '37', '07', '34']

#exemple de les slides

#nom_xifrat = text_to_hex(text_original) 

print(f"Text original: {text_original}")
print(f"Text en hexadecimal: {nom_xifrat}")

## Exercici 2
clau =['2b', '7e', '15', '16', '28', 'ae', 'd2', 'a6', 'ab', 'f7', '15', '88', '09', 'cf', '4f', '3c']


# Definició de la Sbox per a SubBytes
AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Funció per imprimir una matriu en format hexadecimal
def print_state_hex(state, label):
    """Imprimeix la matriu d'estat en format hexadecimal"""
    print(f"\n{label}:")
    for row in state:
        row_hex = [f"{b:02x}" for b in row]
        print(f"[{', '.join(row_hex)}]")

# Funció AddRoundKey
def add_round_key(state, round_key):
    """
    Realitza l'operació XOR entre l'estat actual i la clau de ronda.
    Entrada: state (matriu 4x4 bytes), round_key (matriu 4x4 bytes)
    Sortida: estat després d'aplicar XOR
    """
    result = [[state[i][j] ^ round_key[i][j] for j in range(4)] for i in range(4)]
    return result

def sub_bytes(state):
    """
    Aplica la substitució (S-box).
    Entrada: estat
    Sortida: estat transformat amb S-box
    """
    result = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            result[i][j] = AES_SBOX[state[i][j]]
    return result

def shift_rows(state):
    """
    Realitza el desplaçament cíclic de les files de la matriu d'estat.
    Entrada: estat
    Sortida: estat amb files desplaçades
    """
    result = [[0 for _ in range(4)] for _ in range(4)]
    
    # Fila 0: no es desplaça
    result[0] = state[0].copy()
    
    # Fila 1: desplaçament d'1 posició cap a l'esquerra
    result[1][0] = state[1][1]
    result[1][1] = state[1][2]
    result[1][2] = state[1][3]
    result[1][3] = state[1][0]
    
    # Fila 2: desplaçament de 2 posicions cap a l'esquerra
    result[2][0] = state[2][2]
    result[2][1] = state[2][3]
    result[2][2] = state[2][0]
    result[2][3] = state[2][1]
    
    # Fila 3: desplaçament de 3 posicions cap a l'esquerra
    result[3][0] = state[3][3]
    result[3][1] = state[3][0]
    result[3][2] = state[3][1]
    result[3][3] = state[3][2]
    
    return result

# Funcions auxiliars per a mix_columns
def gmul(a, b):
    """Multiplicació a GF(2^8)"""
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1B  # Polinomi irreductible: x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p & 0xFF

def mix_columns(state):
    """
    Barreja les columnes de l'estat.
    Entrada: estat
    Sortida: estat després del MixColumns
    """
    # Matriu de transformació MixColumns
    mix_matrix = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]
    
    result = [[0 for _ in range(4)] for _ in range(4)]
    
    for i in range(4):  # per cada fila
        for j in range(4):  # per cada columna
            result[i][j] = 0
            for k in range(4):  # per cada element en la multiplicació
                result[i][j] ^= gmul(mix_matrix[i][k], state[k][j])
    
    return result

# Constants per a key_expansion
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]

def sub_word(word):
    """Substitueix cada byte d'una paraula usant la S-box"""
    return [AES_SBOX[byte] for byte in word]

def rot_word(word):
    """Rotació cíclica d'una paraula"""
    return word[1:] + word[:1]

def key_expansion(key):
    """
    Expandeix la clau principal per generar totes les claus de ronda.
    Entrada: Clau original (array de 16 bytes en format string hex)
    Sortida: llista de claus de ronda
    """
    # Convertir les strings hex a bytes
    key_bytes = [[int(key[i*4+j], 16) for j in range(4)] for i in range(4)]
    
    # Transposar la matriu per treballar en format AES (columnes)
    key_bytes = [[key_bytes[j][i] for j in range(4)] for i in range(4)]
    
    # Aplanar per facilitar l'expansió
    key_words = []
    for col in range(4):
        for row in range(4):
            key_words.append(key_bytes[row][col])
    
    # La clau expandida tindrà Nb * (Nr + 1) paraules
    # Per AES-128: Nb=4, Nr=10, per tant 44 paraules (176 bytes)
    expanded_key = [0] * 176
    
    # Copiar la clau original a l'inici de l'expandida
    for i in range(16):
        expanded_key[i] = key_words[i]
    
    # Expandir la clau
    for i in range(4, 44):  # 44 paraules en total
        temp = [expanded_key[(i-1)*4 + j] for j in range(4)]
        
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i//4 - 1]
        
        for j in range(4):
            expanded_key[i*4 + j] = expanded_key[(i-4)*4 + j] ^ temp[j]
    
    # Convertir la clau expandida en format de claus de ronda
    round_keys = []
    for round_num in range(11):  # 11 claus (inicial + 10 rondes)
        round_key = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                round_key[j][i] = expanded_key[round_num*16 + i*4 + j]
        round_keys.append(round_key)
    
    return round_keys

def aes_encrypt(plaintext, key):
    """
    Implementa l'algorisme complet d'AES-128 mostrant els detalls de cada pas.
    Entrada: text pla (matriu 4x4), clau (matriu 4x4)
    Sortida: text xifrat (matriu 4x4)
    """
    # Expandir la clau
    round_keys = key_expansion(key)
    
    # Estat inicial = text pla
    state = plaintext
    print_state_hex(state, "Estat inicial")
    
    # Ronda inicial
    state = add_round_key(state, round_keys[0])
    print_state_hex(state, "Després de la ronda inicial (AddRoundKey)")
    
    # Rondes 1 a 9
    for i in range(1, 10):
        print(f"\n\n======= RONDA {i} =======")
        print_state_hex(state, f"Inici de la ronda {i}")
        
        # SubBytes
        state = sub_bytes(state)
        print_state_hex(state, f"Ronda {i} - Després de SubBytes")
        
        # ShiftRows
        state = shift_rows(state)
        print_state_hex(state, f"Ronda {i} - Després de ShiftRows")
        
        # MixColumns
        state = mix_columns(state)
        print_state_hex(state, f"Ronda {i} - Després de MixColumns")
        
        # AddRoundKey
        state = add_round_key(state, round_keys[i])
        print_state_hex(state, f"Ronda {i} - Després de AddRoundKey")
    
    # Ronda final (sense MixColumns)
    print("\n\n======= RONDA FINAL (10) =======")
    print_state_hex(state, "Inici de la ronda final")
    
    state = sub_bytes(state)
    print_state_hex(state, "Ronda final - Després de SubBytes")
    
    state = shift_rows(state)
    print_state_hex(state, "Ronda final - Després de ShiftRows")
    
    state = add_round_key(state, round_keys[10])
    print_state_hex(state, "Text xifrat final (després de AddRoundKey)")
    
    return state

def main():
    # Si vols canviar el text, modifica la variable text_original al principi del codi
    # Convertir els hexadecimals del nom a valors enters
    text_bytes = [int(h, 16) for h in nom_xifrat]
    
    # Mostrar el text original i la seva representació en bytes
    print(f"\nText en bytes:")
    for i, b in enumerate(text_bytes):
        print(f"{b:02x}", end=" ")
        if (i + 1) % 16 == 0:
            print()
    print("\n")
    
    # Assegurar-se que tenim múltiples de 16 bytes (mida del bloc AES)
    while len(text_bytes) % 16 != 0:
        text_bytes.append(0)  # Padding amb zeros
    
    print(f"Text amb padding (longitud: {len(text_bytes)} bytes):")
    for i, b in enumerate(text_bytes):
        print(f"{b:02x}", end=" ")
        if (i + 1) % 16 == 0:
            print()
    print("\n")
    
    # Processar cada bloc de 16 bytes
    cipher_blocks = []
    for i in range(0, len(text_bytes), 16):
        # Organitzar el bloc en matriu d'estat 4x4 (per columnes)
        block = text_bytes[i:i+16]
        state = [[0 for _ in range(4)] for _ in range(4)]
        for j in range(16):
            state[j % 4][j // 4] = block[j]
        
        print(f"\n\n========== BLOC {i//16 + 1} ==========")
        
        # Xifrar el bloc
        encrypted_state = aes_encrypt(state, clau)
        
        # Convertir l'estat xifrat de nou a llista
        encrypted_block = []
        for col in range(4):
            for row in range(4):
                encrypted_block.append(encrypted_state[row][col])
        
        cipher_blocks.extend(encrypted_block)
    
    # Mostrar el resultat en hexadecimal
    print("\n\n========== RESULTAT FINAL ==========")
    print("Text xifrat (hexadecimal):")
    for i, b in enumerate(cipher_blocks):
        print(f"{b:02x}", end=" ")
        if (i + 1) % 16 == 0:
            print()
    print()

if __name__ == "__main__":
    main()