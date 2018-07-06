import math  ;
import random ;

SBox = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7] ;
SBoxInv = [14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5] ;


P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PInv = [9, 17, 23, 31, 13, 28, 2, 18, 24, 16, 30, 6, 26, 20, 10, 1, 8, 14, 25, 3, 4, 29, 11, 19, 32, 12, 22, 7, 5, 27, 15, 21] ;



SHIFT = [8, 8, 8, 8, 0] ;


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

    # greedy algorithm for now :-(
    @staticmethod
    def compute_differential_path(Delta_X):
        DDT = simple_block_cipher.compute_difference_distribution_table(SBox);
        state = Delta_X ;
        current_proba = 1 ;
        for i in range(simple_block_cipher.nb_round-2): # R-1 Round.
            new_state = 0 ;
            for j in range(8):
                sbox_input = (state >> ((7-j) << 2)) & 0xF ;
                new_state = new_state << 4 ;
                if sbox_input: # != 0
                    max_proba = max(DDT[sbox_input]) ; # Greedy, greedy ;-)
                    delta_y = DDT[sbox_input].index(max_proba) ;
                    current_proba = current_proba*(max_proba/16.0) ;
                    new_state ^= delta_y ;
            state = simple_block_cipher.apply_permutation(P, new_state, 32) ;
        return (state, current_proba) ;


    @staticmethod
    def HW(a):
        return 0 if a == 0 else simple_block_cipher.HW(a >> 1)+(a&1) ;

    @staticmethod
    def iterate_key(delta_y):
        copy_delta_y = delta_y ;
        sbox_pos = [] ;
        for i in range(8):
            if copy_delta_y & 0xF:
                sbox_pos.append(i) ;
            copy_delta_y = copy_delta_y >> 4 ;
        upper_bound = 1 << (len(sbox_pos) << 2) ;
        for i in range(upper_bound):
            key = 0 ;
            for j in range(len(sbox_pos)):
                copy_i = i >> ((len(sbox_pos)-1-j) << 2) & 0xF ;
                key ^= (copy_i << ((7-sbox_pos[j]) << 2)) ;
            yield key ;


    @staticmethod
    def update_state_with_sbox(S, state):
        ret = 0 ;
        for j in range(8):
            sbox_input = state >> ((7 - j) << 2) & 0xF;
            sbox_output = SBoxInv[sbox_input];
            ret = (ret << 4) ^ sbox_output;
        return ret ;


    # 'key' is supposed to be Unknown.
    @staticmethod
    def find_key(delta_X, delta_Y, key, iter = 100):
        key_proba = {} ;
        delta_Z = simple_block_cipher.apply_permutation(P, delta_Y, 32);
        delta_Z = simple_block_cipher.apply_permutation(P, delta_Z, 32);
        for _ in range(iter):
            Plain = random.randint(0, 1 << 32 - 1);
            Plain2 = Plain ^ delta_X;
            Plain = simple_block_cipher.encrypt(Plain, key)
            Plain2 = simple_block_cipher.encrypt(Plain2, key)
            P_ret = simple_block_cipher.apply_permutation(PInv, Plain, 32);
            P_ret = simple_block_cipher.update_state_with_sbox(SBoxInv, P_ret);
            P2_ret = simple_block_cipher.apply_permutation(PInv, Plain2, 32);
            P2_ret = simple_block_cipher.update_state_with_sbox(SBoxInv, P2_ret);
            key_iterator = simple_block_cipher.iterate_key(delta_Z);
            for key in key_iterator:
                Q_ret = P_ret^key ;
                Q2_ret = P2_ret^key ;
                Q_ret = simple_block_cipher.apply_permutation(PInv, Q_ret, 32);
                Q_ret = simple_block_cipher.update_state_with_sbox(SBoxInv, Q_ret);
                Q2_ret = simple_block_cipher.apply_permutation(PInv, Q2_ret, 32);
                Q2_ret = simple_block_cipher.update_state_with_sbox(SBoxInv, Q2_ret);
                # print(">>> "+bin(Q_ret^Q2_ret)[2:].zfill(32)) ;
                if (Q_ret^Q2_ret) == delta_Y:
                    if not(key in key_proba):
                        key_proba[key] = 1 ;
                    else:
                        key_proba[key] += 1;
        return key_proba ;


simple_block_cipher.nb_round = 4 ;


if __name__ == "__main__":
    key = 0xDEADBEEF ;
    plain = 0xCAFEBABA ;
    cipher = simple_block_cipher.encrypt(plain, key) ;

    print(hex(cipher)) ;
    print(hex(simple_block_cipher.decrypt(cipher, key))) ;

    # Z = simple_block_cipher.apply_permutation(P, plain, 32) ;
    # Z = simple_block_cipher.apply_permutation(PInv, Z, 32) ;
    #
    # print(hex(Z)) ;
    #
    # print(simple_block_cipher.compute_inverse_SBox(P)) ;

    A = simple_block_cipher.compute_differential_path(0xB) ;
    delta_Y = A[0] ;
    print(delta_Y)

    proba = simple_block_cipher.find_key(0xB, delta_Y, key);
    print(proba)

