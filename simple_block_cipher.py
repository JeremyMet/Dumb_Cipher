import math  ;
import random ;

SBox = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7] ;
SBoxInv = [14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5] ;


P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PInv = [8, 16, 22, 30, 12, 27, 1, 17, 23, 15, 29, 5, 25, 19, 9, 0, 7, 13, 24, 2, 3, 28, 10, 18, 31, 11, 21, 6, 4, 26, 14, 20] ;


SHIFT = [9, 7, 7, 9, 0] ;


class simple_block_cipher(object):


    @staticmethod
    def apply_SBOX(SBox, val):
        row = (((1 << 5) & val) >> 4) ^ (val & 1) ;
        column = (val & 0x1E) >> 1 ;
        return SBox[row][column] ;

    @staticmethod
    def apply_permutation(P, val, len_val):
        ret = 0 ;
        for p in P:
            ret = (ret << 1) ^ ((val >> (len_val-p)) & 1) ;
        return ret ;

    @staticmethod
    def encrypt(input, key):
        LSH = lambda x, shf: (x << shf ^ x >> (32 - shf)) & 0xFFFFFFFF;
        subkey = key;
        ret = input;
        for i in range(simple_block_cipher.nb_round):
            subkey = LSH(subkey, SHIFT[i]);
            ret ^= subkey;
            tmp_ret = 0;
            for j in range(8):
                sbox_input = ret >> ((7 - j) << 2) & 0xF;
                sbox_output = SBox[sbox_input];
                tmp_ret = (tmp_ret << 4) ^ sbox_output;
            # ret = tmp_ret
            ret = simple_block_cipher.apply_permutation(P, tmp_ret, 32);
        return ret;

    @staticmethod
    def decrypt(input, key):
        LSH = lambda x, shf: (x << shf ^ x >> (32 - shf)) & 0xFFFFFFFF;
        subkey = key;
        ret = input;
        for i in range(simple_block_cipher.nb_round):
            ret = simple_block_cipher.apply_permutation(PInv, ret, 32);
            tmp_ret = 0;
            for j in range(8):
                sbox_input = ret >> ((7 - j) << 2) & 0xF;
                sbox_output = SBoxInv[sbox_input];
                tmp_ret = (tmp_ret << 4) ^ sbox_output;
            ret = tmp_ret;
            subkey = LSH(subkey, 32-SHIFT[4-i]);
            ret ^= subkey;
        return ret;



    @staticmethod
    def compute_inverse_SBox(S):
        ret = [0 for _ in range(len(S))] ;
        for i in range(len(S)):
            ret[S[i]] = i ;
        return ret ;

    @staticmethod
    def compute_difference_distribution_table(S):
        # row => input difference
        # column => output difference
        length = len(S) ;
        ret = [[0 for _ in range(length)] for _ in range(length)] ;
        for i in range(length): # value of x
            for j in range(length): # value of delta x
                sbox_input_y = S[i] ;
                sbox_input_y_s = S[i^j] ;
                delta_x = j ;
                delta_y = sbox_input_y_s^sbox_input_y;
                ret[delta_x][delta_y] += 1 ;
        return ret ;

    @staticmethod
    def compute_differential_path(S, S_index):
        DDT = simple_block_cipher.compute_difference_distribution_table(S);
        current_max = 0 ;
        for l in DDT:
            if max(l) > current_max:
                current_max = max(l) ;
                delta = l.index(current_max) ;
        proba = [0 for _ in range(8)] ;
        tmp_proba = [0 for _ in range(8)] ;
        state = delta << ((7-S_index) << 2) ;
        simple_block_cipher.apply_permutation(P, state, 32);
        for i in range(1,3):
            new_state = 0 ;
            for j in range(8):
                tmp_state = (state >> ((7-j) << 2)) & 0xF ;
                if tmp_state:
                    current_max = max(DDT[tmp_state]) ;
                    new_state = current_max << ((7-j) << 2) ;
                    
                    for k in range(4):
                        current_max
                        pass ;
                state = new_state ;
                simple_block_cipher.apply_permutation(P, state, 32);




        print(delta) ;





simple_block_cipher.nb_round = 4 ;


if __name__ == "__main__":
    key = 0xDEADBEEF ;
    plain = 0x0000000A
    cipher = simple_block_cipher.encrypt(plain, key) ;

    print(hex(cipher)) ;
    print(hex(simple_block_cipher.decrypt(cipher, key))) ;

    print(">>> "+str(P[18]))


    DDT = simple_block_cipher.compute_difference_distribution_table(SBox) ;


    simple_block_cipher.compute_differential_path(SBox, 0xB)
