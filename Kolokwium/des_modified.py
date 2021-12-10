"""
################################################################################################################
ZMIANY w DES:
- klucz zamiast 64 bitów ma teraz wielkość 112 bitów
- blok do zaszyfrowania zamiast 64 bitów ma teraz wielkość 96 bitów
- to czy zostanie zamieniona kolejność L, R podczas rundy zależy teraz od klucza - zainspirowane wariantem RDES
    (powinno utrudnić kryptoanalizę różnicową i liniową)
- permutacja w funkcji F zależy również od klucza, są obecnie 4 różne tablice, ale łatwo dodać więcej
- nie zmieniałem działania sboxów jeśli chodzi o przekształcenie 6 bitów wejściowych w 4 wyjściowe, ale z racji
    zwiększenia klucza musiałem zwiększyć liczbę sboxów do 16 (bo na koniec chcemy 64 bity, więc potrzebujemy
    64/4 = 16 sboxów, a dane wejściowe przed aplikacją sboxów muszą mieć 16*6=96 bitów)
- modyfikacje rozmiarów klucza i bloku wejściowego wymusiły zmiany w funkcjach pomocniczych i rozmiarów tablic
    PC1, PC2 itp.
-usunąłem INITIAL PERMUTATION i INVERSE PERMUTATION bo nie są potrzebne
################################################################################################################
"""

import textwrap

get_bin = lambda x, n: format(x, 'b').zfill(n)


def XOR(bits1, bits2):
    # ciągi muszą być równej długości
    xor_result = ""
    for index in range(len(bits1)):
        if bits1[index] == bits2[index]:
            xor_result += '0'
        else:
            xor_result += '1'
    return xor_result


def intListToBinStr(message_list):
    binary = []
    for x in message_list:
        binary.append(get_bin(x, 8))
    binary_str = ""
    for x in binary:
        binary_str += x

    return binary_str


def intoIntArray(message: str):
    int_array = []
    mesg_array = list(message)
    for i in mesg_array:
        int_array.append(ord(i))
    return int_array


PERMUTATION_TABLE = [
    [18, 47, 31, 8, 16, 26, 21, 58, 34, 0, 40, 29, 37, 42, 15, 54, 38, 52, 46, 35, 1, 2, 56, 11, 5, 63, 24, 48, 3, 55,
     10, 62, 61, 19, 33, 36, 53, 39, 28, 4, 12, 60, 57, 43, 44, 20, 17, 6, 27, 49, 30, 59, 51, 7, 32, 9, 22, 45, 13, 25,
     41, 14, 50, 23],
    [43, 16, 21, 48, 12, 53, 49, 31, 51, 22, 58, 55, 23, 9, 34, 10, 39, 54, 45, 5, 62, 24, 2, 19, 59, 50, 20, 41, 36, 1,
     26, 27, 40, 32, 25, 56, 8, 13, 52, 57, 37, 42, 47, 3, 6, 46, 44, 60, 11, 30, 18, 28, 7, 63, 38, 35, 4, 15, 33, 29,
     61, 14, 17, 0],
    [51, 49, 39, 16, 57, 26, 6, 42, 37, 19, 52, 40, 61, 10, 0, 56, 33, 43, 35, 59, 50, 17, 34, 14, 13, 8, 24, 23, 27,
     11, 18, 7, 48, 30, 32, 4, 9, 41, 29, 2, 60, 45, 20, 12, 1, 47, 44, 36, 25, 55, 15, 5, 54, 22, 28, 38, 63, 21, 3,
     58, 62, 46, 53, 31],
    [5, 39, 16, 55, 29, 45, 43, 27, 33, 15, 14, 51, 21, 42, 44, 52, 49, 34, 53, 56, 7, 62, 40, 58, 50, 36, 25, 46, 20,
     18, 24, 41, 8, 26, 32, 4, 12, 22, 10, 3, 59, 13, 23, 38, 37, 28, 6, 54, 57, 17, 48, 9, 19, 11, 61, 31, 2, 30, 47,
     63, 0, 60, 35, 1],
]


def apply_Permutation(permutation_table, sboxes_output, key):
    """ Scalony efekt użycia Sboksów poddawany jest zdefiniowanej permutacji"""
    permuted32bits = ""
    for index in permutation_table[int(key, 2) % 4]:
        permuted32bits += sboxes_output[index - 1]
    return permuted32bits


EXPANSION_TABLE = [3, 24, 16, 10, 47, 35, 44, 25, 18, 36, 40, 1, 32, 14, 2, 17, 3, 31, 4, 28, 41, 5, 43, 15, 23, 0, 33,
                   38, 1, 7, 8, 0, 15, 12, 20, 9, 13, 8, 2, 26, 11, 4, 11, 46, 34, 10, 13, 21, 42, 12, 45, 6, 30, 6, 9,
                   27, 22, 37, 7, 5, 14, 19, 39, 29]


def apply_Expansion(expansion_table, bits48):
    """ Rozszerza 48-bitowy blok do 64 bitów, używając zadanego schematu"""
    bits64 = ""
    for index in expansion_table:
        bits64 += bits48[index - 1]
    return bits64


def split64bits_in_6bits(XOR_64bits):
    """Podział bloku 48-bitowego na 6-bitowe porcje """
    list_of_6bits = textwrap.wrap(XOR_64bits, 6)
    return list_of_6bits


def split96bits_in_half(binarybits):
    return binarybits[:48], binarybits[48:]


def binary_to_decimal(binarybits):
    """ Konwersja łańcucha bitów do wartości dzięsiętnej """
    decimal = int(binarybits, 2)
    return decimal


def decimal_to_binary(decimal):
    """ Konwersja wartości dziesiętnej do 4-bitowego łańcucha bitów """
    binary4bits = bin(decimal)[2:].zfill(4)
    return binary4bits


def circular_left_shift(bits, numberofbits):
    shiftedbits = bits[numberofbits:] + bits[:numberofbits]
    return shiftedbits


PC1 = [5, 7, 39, 83, 46, 24, 11, 62, 52, 81, 0, 22, 54, 72, 77, 74, 68, 70, 31, 23, 40, 55, 20, 84, 29, 51, 32, 42, 14,
       67, 50, 17, 25, 26, 87, 64, 49, 41, 79, 43, 6, 45, 73, 2, 21, 1, 56, 47, 48, 12, 85, 27, 66, 37, 60, 58, 15, 28,
       36, 35, 44, 34, 82, 9, 61, 3, 10, 63, 65, 18, 71, 57, 76, 75, 59, 30, 86, 53, 19, 13, 69, 78, 16, 80, 38, 33, 4,
       8]


def apply_PC1(pc1_table, keys_112bits):
    keys_88bits = ""
    for index in pc1_table:
        keys_88bits += keys_112bits[index]
    return keys_88bits


PC2 = [48, 6, 20, 27, 39, 10, 55, 60, 50, 11, 12, 31, 32, 61, 35, 63, 23, 16, 26, 24, 22, 4, 36, 42, 0, 51, 3, 18, 28,
       19, 17, 1, 53, 29, 45, 33, 2, 7, 52, 49, 30, 62, 9, 43, 5, 38, 54, 13, 47, 21, 57, 25, 46, 8, 15, 44, 37, 41, 59,
       56, 58, 34, 40, 14]


def apply_PC2(pc2_table, keys_88bits):
    keys_64bits = ""
    for index in pc2_table:
        keys_64bits += keys_88bits[index]
    return keys_64bits


def split88bits_in_half(keys_112bits):
    left_keys, right_keys = keys_112bits[:44], keys_112bits[44:]
    return left_keys, right_keys


def generate_keys(key_112bits):
    round_keys = []
    keys_88bits = apply_PC1(PC1, key_112bits)
    left88, right88 = split88bits_in_half(keys_88bits)

    for i in range(16):
        if i in [0, 1, 8, 15]:
            left88 = circular_left_shift(left88, 1)
            right88 = circular_left_shift(right88, 1)
        else:
            left88 = circular_left_shift(left88, 2)
            right88 = circular_left_shift(right88, 2)

        subkey = apply_PC2(PC2, left88 + right88)
        round_keys.append(subkey)

    return round_keys


SBOX = [
    # Box-1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # Box-2

    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],

    # Box-3

    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]

    ],

    # Box-4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],

    # Box-5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # Box-6

    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]

    ],
    # Box-7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # Box-8

    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ],
    # Box-9
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # Box-10

    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],

    # Box-11

    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]

    ],

    # Box-12
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],

    # Box-13
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # Box-14

    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]

    ],
    # Box-15
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # Box-16

    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]


def sbox_lookup(sboxcount, first_last, middle4):
    """ Dostęp do odpowiedniej wartości odpowiedniego sboxa"""
    d_first_last = binary_to_decimal(first_last)
    d_middle = binary_to_decimal(middle4)
    sbox_value = SBOX[sboxcount][d_first_last][d_middle]
    return decimal_to_binary(sbox_value)


def functionF(pre48bits, key64bits):
    out_bits64 = apply_Expansion(EXPANSION_TABLE, pre48bits)  # roszerzenie bloku 48 bitów do 64 bitów
    xor_bits = XOR(out_bits64, key64bits)  # xor z kluczem
    xor_bits96 = xor_bits + xor_bits[:32]  # można zamienić na funkcję apply expansion ale różnica niewielka
    six_bit_blocks = split64bits_in_6bits(xor_bits96)  # podział bloku na bloki 6-bitowe
    sboxes_applied = [sbox_lookup(i, block[0] + block[-1], block[1:5]) for i, block in
                      enumerate(six_bit_blocks)]  # aplikacja sboxów
    merged_4bits = "".join(sboxes_applied)
    final64bits = apply_Permutation(PERMUTATION_TABLE, merged_4bits,
                                    key64bits)  # permutacja z wykorzystaniem klucza -> określa którą tablicę permutacji używamy
    return final64bits


def DES_encrypt(message, key):
    subkeys = generate_keys(key)
    L, R = split96bits_in_half(message)

    for i in range(16):
        f_output = functionF(R, subkeys[i])
        if int(subkeys[i], 2) % 3 == 0:  # zamiana miejsc zależy od klucza
            L, R = R, XOR(L, f_output)
        else:
            R, L = R, XOR(L, f_output)
    return R + L


def DES_decrypt(message, key):
    subkeys = generate_keys(key)[::-1]
    L, R = split96bits_in_half(message)
    for i in range(16):
        if int(subkeys[i], 2) % 3 != 0:  # zamiana miejsc zależy od klucza
            L, R = R, L
        f_output = functionF(R, subkeys[i])
        L, R = R, XOR(L, f_output)

    return R + L


M = "testowa wiadomosc"
key = "testowy klucz do zaszyfrowania"

plaintext = intListToBinStr(intoIntArray(M))[:96]
print("Plaintext (96 bits):     ", plaintext)
binary_key = intListToBinStr(intoIntArray(key))
print("Key (only 112 bits):     ", binary_key[:112])

encrypted = DES_encrypt(plaintext, binary_key[:112])
print("Encrypted message:       ", encrypted)
decrypted = DES_decrypt(encrypted, binary_key[:112])
print("Decrypted message:       ", decrypted)
print("XOR(plaintext, decrypted)", XOR(plaintext, decrypted))
