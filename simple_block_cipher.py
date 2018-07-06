import math  ;
import random ;
import numpy ;

SBox = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7] ;
SBoxInv = [14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5] ;


P = [8, 0, 10, 5, 3, 12, 13, 14, 11, 6, 9, 7, 2, 4, 15, 1] ;
PInv = [1, 15, 12, 4, 13, 3, 9, 11, 0, 10, 2, 8, 5, 6, 7, 14] ;




SHIFT = [4, 4, 4, 4, 0] ;


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
            ret = (ret << 1) ^ ((val >> (len_val-p-1)) & 1) ;
        return ret ;

    @staticmethod
    def encrypt(input, key):
        LSH = lambda x, shf: (x << shf ^ x >> (16 - shf)) & 0xFFFF;
        subkey = key;
        ret = input;
        for i in range(simple_block_cipher.nb_round):
            subkey = LSH(subkey, SHIFT[i]);
            ret ^= subkey;
            tmp_ret = 0;
            for j in range(4):
                sbox_input = ret >> ((3 - j) << 2) & 0xF;
                sbox_output = SBox[sbox_input];
                tmp_ret = (tmp_ret << 4) ^ sbox_output;
            # ret = tmp_ret
            ret = simple_block_cipher.apply_permutation(P, tmp_ret, 16);
        ret ^= key ;
        return ret;

    @staticmethod
    def decrypt(input, key):
        RSH = lambda x, shf: (x >> shf ^ x << (16 - shf)) & 0xFFFF;
        subkey = key;
        ret = input^key;
        for i in range(simple_block_cipher.nb_round):
            ret = simple_block_cipher.apply_permutation(PInv, ret, 16);
            tmp_ret = 0;
            for j in range(4):
                sbox_input = ret >> ((3 - j) << 2) & 0xF;
                sbox_output = SBoxInv[sbox_input];
                tmp_ret = (tmp_ret << 4) ^ sbox_output;
            ret = tmp_ret;
            subkey = RSH(subkey, SHIFT[4-i]);
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

    # greedy algorithm for now :-(
    @staticmethod
    def compute_differential_path(Delta_X):
        DDT = simple_block_cipher.compute_difference_distribution_table(SBox);
        state = Delta_X ;
        current_proba = 1 ;
        for i in range(simple_block_cipher.nb_round-1): # R-1 Round.
            new_state = 0 ;
            for j in range(4):
                sbox_input = (state >> ((3-j) << 2)) & 0xF ;
                new_state = new_state << 4 ;
                if sbox_input: # != 0
                    max_proba = max(DDT[sbox_input]) ; # Greedy, greedy ;-)
                    delta_y = DDT[sbox_input].index(max_proba) ;
                    current_proba = current_proba*(max_proba/16.0) ;
                    new_state ^= delta_y ;
            state = simple_block_cipher.apply_permutation(P, new_state, 16) ;
        return (state, current_proba) ;


    @staticmethod
    def HW(a):
        return 0 if a == 0 else simple_block_cipher.HW(a >> 1)+(a&1) ;

    @staticmethod
    def iterate_key(delta_y):
        copy_delta_y = delta_y ;
        sbox_pos = [] ;
        for i in range(4):
            if copy_delta_y & 0xF:
                sbox_pos.append(i) ;
            copy_delta_y = copy_delta_y >> 4 ;
        upper_bound = 1 << (len(sbox_pos) << 2) ;
        # print(sbox_pos);
        # print(upper_bound) ;
        # input();
        for i in range(upper_bound):
            key = 0 ;
            for j in range(len(sbox_pos)):
                copy_i = i >> ((len(sbox_pos)-1-j) << 2) & 0xF ;
                key ^= (copy_i << ((sbox_pos[j]) << 2)) ;
            yield key ;


    @staticmethod
    def update_state_with_sbox(S, state):
        ret = 0 ;
        for j in range(4):
            sbox_input = state >> ((3 - j) << 2) & 0xF;
            sbox_output = S[sbox_input];
            ret = (ret << 4) ^ sbox_output;
        return ret ;


    # 'key' is supposed to be Unknown.
    @staticmethod
    def find_key(delta_X, delta_Y, key, iter = 10000):
        key_proba = {} ;
        delta_Z = simple_block_cipher.apply_permutation(P, delta_Y, 16) ;
        for _ in range(iter):
            Plain = random.randint(0, 1 << 16 - 1);
            Plain2 = Plain ^ delta_X;
            Cipher = simple_block_cipher.encrypt(Plain, key)
            Cipher2 = simple_block_cipher.encrypt(Plain2, key)
            key_iterator = simple_block_cipher.iterate_key(delta_Z) ;
            for key in key_iterator:
                # print("key >>> "+bin(key)[2:].zfill(16)) ;
                Q_ret = Cipher^key ;
                Q2_ret = Cipher2^key ;
                Q_ret = simple_block_cipher.apply_permutation(PInv, Q_ret, 16);
                Q_ret = simple_block_cipher.update_state_with_sbox(SBoxInv, Q_ret);
                Q2_ret = simple_block_cipher.apply_permutation(PInv, Q2_ret, 16);
                Q2_ret = simple_block_cipher.update_state_with_sbox(SBoxInv, Q2_ret);
                # print(">>> "+bin(Q_ret^Q2_ret)[2:].zfill(16)) ;
                if (Q_ret^Q2_ret) == delta_Y:
                    if not(key in key_proba):
                        key_proba[key] = 1 ;
                    else:
                        key_proba[key] += 1;
        return key_proba ;


simple_block_cipher.nb_round = 4 ;


if __name__ == "__main__":
    key = 0x0ECA ;
    plain = 0xDEAD ;
    cipher = simple_block_cipher.encrypt(plain, key) ;

    print(hex(cipher)) ;
    print(hex(simple_block_cipher.decrypt(cipher, key))) ;

    # Z = simple_block_cipher.apply_permutation(P, plain, 32) ;
    # Z = simple_block_cipher.apply_permutation(PInv, Z, 32) ;
    #
    # print(hex(Z)) ;
    #
    # print(simple_block_cipher.compute_inverse_SBox(P)) ;

    # for _ in range(100000):
    #     I = random.randint(0, 1 << 16 -1) ;
    #     A = simple_block_cipher.compute_differential_path(I) ;
    #     if simple_block_cipher.HW(A[0]) <= 2 and A[1] > 1/100.0:
    #         print("Found !!!")
    #         print(bin(I)) ;
    #         print(bin(A[0])) ;
    #         print(A[1])
    #         break ;
    #
    # delta_Y = A[0] ;
    # print(bin(delta_Y)) ;
    # print(A[1]) ;

    delta_X = 0b110100100000 ;
    delta_Y = 0b100000000001 ;
    iter = simple_block_cipher.iterate_key(delta_Y) ;
    for i, val in enumerate(iter):
        print(str(i)+"  "+bin(val)[2:].zfill(16))
    #
    proba = simple_block_cipher.find_key(delta_X, delta_Y, key);

    for k, v in proba.items():
        tmp_k = bin(k)[2:].zfill(16) ;
        print(tmp_k+" "+str(v)) ;
    #

    # A = 0xDEAD ;
    # B = simple_block_cipher.apply_permutation(P, A, 16) ;
    # C = simple_block_cipher.apply_permutation(PInv, B, 16) ;
    # print(hex(A)) ;
    # print(hex(C)) ;

