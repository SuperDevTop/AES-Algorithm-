from typing import List, Union, Tuple, Any, Generator
from itertools import chain
import warnings
import os

ECB = 1
CBC = 2


S_box = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]


Inv_S_box = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d],
]


Rcon = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
    0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4,
    0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
)


def xtime(a): return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def _split(a: List[bytes], n: int) -> List[List[bytes]]:
    """
    Splits a list into a list of n sub-lists. Assumes that len(a) % n == 0
    :param a: the list to split
    :param n: number of parts to split the list into
    :return: a list containing the parts of the source list
    """
    k, m = divmod(len(a), n)
    return list(a[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))


def _chunk(l: List[Any], n: int) -> Generator:
    """
    Chunks the provided list into sub-lists, each containing n items. Assumes that len(l) % n == 0
    :param l: the list to chunk
    :param n: number of elements in each chunk
    """
    for i in range(0, len(l), n):
        yield l[i:i + n]


def _g(block: List[int], rc: bytes) -> List[bytes]:
    """
    Performs the confusion step when expanding the key to roundkeys
    :param block: the block to operate on
    :param rc: the rcon value to use
    :return: the transformed block
    """
    block = [__sub_byte(b, S_box) for b in block[1:] + [block[0]]]
    return [block[0] ^ rc] + block[1:]


def __sub_byte(b: int, box: List[List[bytes]]) -> bytes:
    """
    Performs the substitution from one byte to another from the provided S-box
    :param b: the byte to substitute
    :param box: the box to pick substitution values from
    :return: the substituted byte
    """
    b = hex(b)[2:]
    if len(b) == 1:
        b = '0' + b
    row, col = list(b)
    return box[int(row, 16)][int(col, 16)]


def _sub_bytes(state, box):
    new_mat = []
    for row in state:
        new_row = []
        for v in row:
            new_row.append(__sub_byte(v, box))
        new_mat.append(new_row)
    return new_mat


def _shift_rows(s: List[List[bytes]]) -> List[List[bytes]]:
    """
    Performs the shift rows transformation as described in the standard
    :param s: the state matrix
    :return: the new state matrix with shifted rows
    """
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]
    return s


def _inv_shift_rows(s: List[List[bytes]]) -> List[List[bytes]]:
    """
    Performs the inverted shift rows transformation as described in the standard
    :param s: the state matrix
    :return: the new state matrix with shifted rows
    """
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]
    return s


def _round(state: List[List[bytes]], round_key: List[Union[List[List[int]], List[list]]]) -> List[List[int]]:
    """
    Performs a complete round over a block using the provided roundkey
    :param state: the state matrix before the round transformations
    :param round_key: the round key to use for this round
    :return: state matrix after the round transformations have been applied
    """
    state = _sub_bytes(state, S_box)
    state = _shift_rows(state)
    state = _mix_columns(state)
    state = _add_round_key(state, round_key)
    return state


def _inv_round(state: List[List[bytes]], round_key: List[Union[List[List[int]], List[list]]]) -> List[List[int]]:
    """
    Performs a complete inverse round over a block using the provided roundkey
    :param state: the state matrix before the inverse round transformations
    :param round_key: the round key to use for this round
    :return: state matrix after the inverse round transformations have been applied
    """
    state = _inv_shift_rows(state)
    state = _sub_bytes(state, Inv_S_box)
    state = _add_round_key(state, round_key)
    state = _inv_mix_columns(state)
    return state


def __mix_column(col: List[bytes]) -> List[bytes]:
    """
    Mixes a single column
    :param state: The column to mix
    :return: The mixed column
    """
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= t ^ xtime(col[0] ^ col[1])
    col[1] ^= t ^ xtime(col[1] ^ col[2])
    col[2] ^= t ^ xtime(col[2] ^ col[3])
    col[3] ^= t ^ xtime(col[3] ^ u)
    return col


def _mix_columns(state:  List[List[bytes]]) -> list:
    """
    Performs the mix column transformation as described by the standard.
    :param state: The current state
    :return: The state with mixed columns
    """
    return [__mix_column(column) for column in state]


def _inv_mix_columns(state:  List[List[bytes]]) -> list:
    """
    Performs the inverse mix column transformation as described by the standard.
    :param state: The current state
    :return: The state with mixed columns
    """
    for s in state:
        u = xtime(xtime(s[0] ^ s[2]))
        v = xtime(xtime(s[1] ^ s[3]))
        s[0] ^= u
        s[1] ^= v
        s[2] ^= u
        s[3] ^= v
    return _mix_columns(state)


def _add_round_key(state: List[List[bytes]], round_key: List[Union[List[List[int]], List[list]]]) -> list:
    """
    Applies the current round key to the state matrix.
    :param state: the current state matrix
    :param round_key: the current round key
    :return: the new state after the round key has been applied
    """
    new_state = []
    for r1, r2 in zip(state, round_key):
        new_col = []
        for v1, v2 in zip(r1, r2):
            new_col.append(v1 ^ v2)
        new_state.append(new_col)
    return new_state


def _pad_data(data: bytes, n: int = 16) -> bytes:
    """
    Adds padding to the data according to the PKCS7 standard.
    Note that at least one byte of padding is guaranteed to be added.
    :param data: the data to pad
    :param n: the length to pad the data to, defaults to 16
    :return: the padded data
    """
    pad_len = n - (len(data) % n)
    return data + bytes([pad_len] * pad_len)


def _unpad_data(data: bytes) -> bytes:
    """
    Removes padding from the data according to PKCS7 standard and returns data such that
    len(new_data) = len(data) - pad_len
    :param data: the data to unpad
    :return: the original data without padding
    """
    return data[:-data[-1]]


NUM_ROUNDS = {16: 10, 24: 12, 32: 14}
NUM_WORDS = {16: 4, 24: 6, 32: 8}


class AES:
    def __init__(self, key: bytes, mode=CBC):
        if len(key) not in NUM_ROUNDS:
            raise ValueError("Only 128, 192 and 256 bit keys are supported!")

        if mode != CBC and mode != ECB:
            raise ValueError("Unsupported mode!")

        self.nb = 4
        self.nk = NUM_WORDS[len(key)]
        self.nr = NUM_ROUNDS[len(key)]
        self.mode = mode
        self.block_length = 16
        self.round_keys = self._expand_key(key)

    def _expand_key(self, key: bytes) -> List[Tuple[Any]]:
        """
        Performs operations to expand the key into the respective round keys.
        Uses class fields to determine how many keys to produce.
        :param key: the original key
        :return: list containing the expanded keys
        """
        w = []
        for i in range(self.nk):
            w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

        for i in range(self.nk, (self.nb * (self.nr + 1))):
            tmp = w[i - 1]
            if i % self.nk == 0:
                tmp = _g(tmp, Rcon[int(i / self.nk) - 1])
            elif self.nk > 6 and i % self.nk == self.nb:
                tmp = _sub_bytes([tmp], S_box)[0]
            w.append([x ^ y for x, y in zip(w[i - self.nk], tmp)])
        return list(zip(*[iter(w)] * self.nb))

    def encrypt(self, data: bytes, iv=None) -> tuple:
        """
        Encrypts a single block of data using the AES algorithm as
        described by: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf.
        Under CBC mode, a randomized IV is used and returned from this function along with the result of the
        encryption, it is the responsibility of the user to keep track of the IV.
        :param iv: Optional IV to use in CBC mode. If unset, a random IV will be used
        :param data: The data to encrypt
        :return: a tuple where the first element is the encrypted data.
                Under CBC mode, the second value is the IV used, under ECB mode, the second value is None
        """
        if self.mode == ECB and iv is not None:
            warnings.warn("Initialization vector not used in ECB mode. Providing an IV under ECB mode "
                          "is a no-op but it might indicate an error in you program")

        if self.mode == CBC and iv is None:
            iv = os.urandom(self.block_length)

        state = _pad_data(data)
        blocks = list(_chunk(list(state), self.block_length))

        cipher = self._encrypt_CBC(blocks, iv) if self.mode == CBC else self._encrypt_ECB(blocks)

        return cipher, iv

    def _encrypt_ECB(self, blocks: List[bytes]) -> bytes:
        """
        Performs ECB mode encryption of the provided blocks
        :param blocks: the blocks to encrypt
        :return: the encrypted bytes
        """
        return b''.join([self._encrypt_single_block(block) for block in blocks])

    def _encrypt_CBC(self, blocks: List[bytes], iv: bytes) -> bytes:
        """
        Performs CBC mode encryption of the provided blocks
        :param blocks: the blocks to encrypt
        :param iv: the iv to use when encrypting
        :return: the encrypted data
        """
        encrypted_blocks = [iv]
        for block, prev in zip(blocks, encrypted_blocks):
            next_block = bytes([x ^ y for x, y in zip(block, prev)])
            encrypted_blocks.append(self._encrypt_single_block(next_block))

        return b''.join(encrypted_blocks[1:])

    def _encrypt_single_block(self, data: bytes) -> bytes:
        """
        Performs encryption of a single block of the AES algorithm, unlike the encrypt method which will encrypt at
        least two blocks as it adds padding
        :param data:
        :return: encrypted block
        """
        state = _split(list(data), 4)
        state = _add_round_key(state, self.round_keys[0])

        for i in range(1, self.nr):
            state = _round(state, self.round_keys[i])

        state = _sub_bytes(state, S_box)
        state = _shift_rows(state)
        state = _add_round_key(state, self.round_keys[-1])

        state = bytes(list(chain(*state)))

        return state

    def decrypt(self, data: bytes, iv=None) -> bytes:
        """
        Decrypts data that were previously encrypted using the encrypt function of this instance. Of course, data
        that were previously encrypted elsewhere could also be decrypted using this method, provided the same
        configuration were used when encrypting.
        :param data: The data to decrypt
        :param iv: The initialization vector that were used for encryption (returned from encrypt function)
        :return: The decrypted bytes
        """
        blocks = list(_chunk(list(data), self.block_length))
        decrypted = self._decrypt_CBC(blocks, iv) if self.mode == CBC else self._decrypt_ECB(blocks)
        return _unpad_data(decrypted)

    def _decrypt_CBC(self, blocks: List[bytes], iv: bytes) -> bytes:
        """
        Performs CBC mode decryption of the provided blocks
        :param blocks: the blocks to decrypt
        :param iv: the iv that were used when encrypting
        :return: the unencrypted data
        """
        blocks = [iv] + blocks
        decrypted_blocks = []
        i = 1
        while i < len(blocks):
            block = blocks[-i]
            block = self._decrypt_single_block(block)
            block = bytes([x ^ y for x, y in zip(block, blocks[-(i + 1)])])

            decrypted_blocks = [block] + decrypted_blocks
            i += 1

        return b''.join(decrypted_blocks)

    def _decrypt_ECB(self, blocks: List[bytes]) -> bytes:
        """
        Decrypts the provided blocks using ECB mode
        :param blocks: the blocks to decrypt
        :return: the decrypted data
        """
        return b''.join([self._decrypt_single_block(block) for block in blocks])

    def _decrypt_single_block(self, data: bytes) -> bytes:
        """
        Performs decryption of a single block of the AES algorithm, unlike the decrypt method which will
        assume that there are padding at the end of the last block.
        :param data: the data to decrypt
        :return: decrypted block
        """
        state = _split(list(data), 4)
        state = _add_round_key(state, self.round_keys[-1])

        for i in range(self.nr - 1, 0, -1):
            state = _inv_round(state, self.round_keys[i])

        state = _inv_shift_rows(state)
        state = _sub_bytes(state, Inv_S_box)
        state = _add_round_key(state, self.round_keys[0])

        state = bytes(list(chain(*state)))
        return state
