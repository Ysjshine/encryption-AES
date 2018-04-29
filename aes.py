import constVar
import numpy as np

class AES:
    def __init__(self,src,key):
        '''
        constructor
        :param src:plain text or cypher text
        :param key:key
        '''
        self.__src = src
        self.__key = key

    def __index_sbox(self, num,type):
        '''
        search in sbox or inv_sbox
        :param num:input byte
        :param type:decode or encode
        :return:output byte
        '''
        temp = int(num)
        #get left 4 bits of input byte
        row = (temp & 0xf0) >> 4
        #get right 4 bits of input byte
        col = temp & 0x0f
        if type == 0:return constVar.sbox[row][col]
        else:return constVar.inv_sbox[row][col]

    def __sub_bytes(self, src,type):
        '''
        :param src:input data
        :param type:decode or encode
        :return:output
        '''
        ans = np.zeros((4,4),dtype=np.int64)
        for i in range(4):
            for j in range(4):
                ans[i][j] = self.__index_sbox(src[i][j],type)
        return ans

    def __shift_row(self, src,type):
        '''
        shift rows:
        1.forward
        the first row does nothing,the second moves a byte to left,
        the third moves 2 bytes and the last moves 3 bytes
        2. inverse:
        the first row does nothing,the second moves a byte to right,
        the third moves 2 bytes and the last moves 3 bytes
        :param src: input
        :param type: decode or encode
        :return:output
        '''
        ans = np.zeros((4,4),dtype=np.int64)
        # for left_num in range(4):
        for i in range(4):
            for j in range(4):
                if type == 0:ans[i][(j-i+4)%4] = src[i][j]
                else:ans[i][(j+i)%4] = src[i][j]
        return ans

    def __GF28mul(self, op1, op2):
        '''
        bytes' multiplicative operation in GF(2^8) field
        :param op1:the first operand
        :param op2:the second operand
        :return:answer
        '''
        ans = []; var = op2; total = 0
        for i in range(8):
            x = (var&constVar.GF_bit[7])
            ans.append(var)
            if x == 0:var = (var << 1)&0xff
            elif x == 0x80:var = ((var<<1)&0xff)^0x1b

        for i in range(8):
            if op1&constVar.GF_bit[i] == 1<<i:
                total = total^ans[i]
        return total

    def __mix_column(self, src,type):
        '''
        mix column operation
        :param src: input
        :param type: decode or encode
        :return: output
        '''
        ans = np.zeros((4,4),dtype=np.int64)
        for i in range(4):
            for k in range(4):
                sum = 0
                for j in range(4):
                    if type == 0:sum =sum^self.__GF28mul(constVar.mix_mat[i][j], src[j][k])
                    else:sum = sum ^ self.__GF28mul(constVar.inv_mix_mat[i][j], src[j][k])
                ans[i][k] += sum
        return ans

    def __calculate_ti(self, w, i):
        '''
        calculate the middle variables ti
        :param w: w[i-1]
        :param i: the sequence number
        :return: output
        '''
        #make sure that w is 32-bits
        w1 = w&0xffffffff
        #move a byte to left then add the  byte to the tail
        p = ((w1&0xff000000)>>24)^((w1<<8)&0xffffffff)
        #sbox
        x1 = self.__index_sbox(p & 0x000000ff,0)
        x2 = self.__index_sbox((p & 0x0000ff00) >> 8,0)
        x3 = self.__index_sbox((p & 0x00ff0000) >> 16,0)
        x4 = self.__index_sbox((p & 0xff000000) >> 24,0)

        ans = ( x1 ^ (x2 << 8) ^ (x3 << 16 )^( x4 <<24))^constVar.round_constant[i]
        # print("ti",hex(ans))
        return ans

    def __generate_init(self, i):
        '''
        get w0,w1,w2,w3
        '''
        key = self.__key
        return (key[4*i]<<24)^(key[4*i+1]<<16)^(key[4*i+2]<<8)^(key[4*i+3])

    def __expand_key(self):
        '''
        expand key and get round keys
        :return:round keys
        '''
        round_key = []; w = np.zeros(100,dtype=np.int64)
        for i in range(4):
            w[i] = self.__generate_init(i)

        for i in range(4,44):
            if i % 4 == 0:
                w[i] = self.__calculate_ti(w[i - 1], int(i / 4) - 1) ^ w[i - 4]
            else:
                w[i] = w[i-1]^w[i-4]

        #divide w[i] into 4 bytes
        for i in range(44):
            if i % 4 != 0:continue
            key = []; bit = 0xff000000
            for j in range(4):
                for k in range(4):
                    key.append((w[i+j]&(bit>>(k*8)))>>(24-k*8))
            round_key.append(key)
        return round_key

    def __add_round_key(self, round_key_i, src):
        '''
        :param round_key_i: i_th round_key
        :param src: input
        :return: output
        '''
        round_key = np.array(round_key_i).reshape((4,4)).T
        # print("----add round key----")
        # self.debug(round_key)
        ans = np.zeros((4,4),dtype=np.int64)
        for i in range(4):
            for j in range(4):
                ans[i][j] = src[i][j]^round_key[i][j]

        return ans

    #encode
    def encode(self):
        round_key = self.__expand_key()
        ans = self.__add_round_key(round_key[0], self.__src)
        for i in range(1,10):
            sub_ans = self.__sub_bytes(ans,0)
            shift_ans = self.__shift_row(sub_ans,0)
            mix_ans = self.__mix_column(shift_ans,0)
            # self.debug(ans)
            # self.debug(sub_ans)
            # self.debug(shift_ans)
            # self.debug(mix_ans)
            ans = self.__add_round_key(round_key[i], mix_ans)
        sub_ans = self.__sub_bytes(ans,0)
        shift_ans = self.__shift_row(sub_ans,0)
        result = self.__add_round_key(round_key[10], shift_ans)
        return result

    #decode
    def decode(self):
        round_key = self.__expand_key()
        ans = self.__add_round_key(round_key[10],self.__src)
        for i in range(9,0,-1):
            inv_shift_ans = self.__shift_row(ans,1)
            inv_sub_ans = self.__sub_bytes(inv_shift_ans,1)
            add_ans = self.__add_round_key(round_key[i],inv_sub_ans)
            # self.debug(ans)
            # self.debug(inv_shift_ans)
            # self.debug(inv_sub_ans)
            # self.debug(add_ans)
            ans = self.__mix_column(add_ans,1)
        inv_shift_ans = self.__shift_row(ans,1)
        inv_sub_ans = self.__sub_bytes(inv_shift_ans,1)
        result = self.__add_round_key(round_key[0],inv_sub_ans)
        return result

    def debug(self,ans):
        for i in range(4):
            for j in range(4):
                print(hex(int(ans[i][j])), end=" ")
                if j == 3:print("")
        print("\n")

if __name__ == '__main__':
    src = np.array([
        [0x32,0x43,0xf6,0xa8],
        [0x88,0x5a,0x30,0x8d],
        [0x31,0x31,0x98,0xa2],
        [0xe0,0x37,0x07,0x34]
    ],dtype=np.int64)

    key = np.array([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c],dtype=np.int64)
    aes = AES(src.T,key)
    ans = aes.encode()

    aes1 = AES(np.array(ans,dtype=np.int64),key)
    ans2 = aes1.decode()

    for i in range(4):
        for j in range(4):
            print(hex(int(ans[i][j])),end=" ")
    print(" ")
    for i in range(4):
        for j in range(4):
            print(hex(int(ans2[i][j])),end=" ")










