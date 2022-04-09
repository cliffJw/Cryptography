import binascii
from operator import ne
import binascii
import Cryptodome.Protocol.KDF


def pass_2_key(password):
    key = binascii.hexlify(Cryptodome.Protocol.KDF.PBKDF2(password, b'Be My Guest', 64))
    key_bin = "{0:08b}".format(int(key, 32))
    return key_bin
    

########  OPERATION ON KEY #########
def key_length_op(chunk, key_bin):
    pt_chunk_len = len(chunk)
    key_len = len(key_bin)
    if key_len > pt_chunk_len:
        fin_key = key_bin[:pt_chunk_len]
    else:
        key_factor = int(pt_chunk_len/key_len) + 1
        fin_key = (key_bin*key_factor)[:pt_chunk_len]
    return fin_key
########  Prepare PT for Chunking PADDING #######
def padding(chunk, num):
    len_data = len(chunk)
    if len_data % num == 0:
        new_chunk = chunk
    else:
        while len_data % num != 0:
            new_chunk = chunk.zfill(len_data + 1)
            len_data += 1 
    return new_chunk
########  Chunk Length ############
def chunks(chunk, num_chunks):
    chunk_len = int(len(chunk)/num_chunks)
    return chunk_len

################   XOR Function  #########
def xora(data_bin, key):
    len_data = len(data_bin)
    xored_data = (int(data_bin, 2) ^ int(key, 2))
    xored_data_bin = format(xored_data, 'b').zfill(len_data)
    return xored_data_bin
    

####### SHIFT OPERATION ###########
def shifta(data, num_shift):
    new_data = data[num_shift:] + data[:num_shift]
    return new_data

########### Reversor ########
def reversa(data):
    rev_data = data[::-1]
    return rev_data
def to_bin_convertor(data):
    data_bin = bin(int(binascii.hexlify(data.encode()), 16))[2:]
    return data_bin


class Cliff:
#     def __init__(self):
#         super(Cliff, self).__init__()

#         text_input = input("Enter text: ")
#         passwd = input("Enter password: ")

#         # self.encrypta(text_input, passwd)
#         self.decrypta(text_input, passwd)

    def encrypta(self, pt, encpasswd):
        ########### To BINARY CONVERSION #####
        plain_txt_bin = to_bin_convertor(pt)
        print("Binary plaintext: ", plain_txt_bin)
        passwd_bin = pass_2_key(encpasswd)
        # print("Binary password: ", passwd_bin)
        
        len_pt_bin = len(plain_txt_bin)
        # print("PT Length UNPADED: ", len_pt_bin)
        new_plain_txt_bin = padding(plain_txt_bin, 4)
        len_new_pt_bin = len(new_plain_txt_bin)
        print("New PT bin:  ", new_plain_txt_bin)
        # print("PT Binary Length:  ", len_new_pt_bin) 
        len_pt = '{0:08b}'.format(len_new_pt_bin).zfill(256) 
        # print("final PT Binary Length:  ", len_pt)  
###################      ENCRYPTION     #####################
        ############## XOR with key #################
        fin_key = key_length_op(new_plain_txt_bin, passwd_bin)
        fin_p_text_xored = xora(new_plain_txt_bin, fin_key)
        print("fin_p_text_xored: ", fin_p_text_xored)

        # divide pt into two equal chunks
        chunk_length = chunks(fin_p_text_xored, 2)
        # print("Plain text bits: ", new_plain_txt_bin)
        chunk1 = fin_p_text_xored[:chunk_length]
        print("Chunk1: ", chunk1)
        chunk2 = fin_p_text_xored[chunk_length:]
        print("Chunk2: ", chunk2)
        ######### Right Shift Chunk 2 by 5 #########
        chunk2_rshift5 = shifta(chunk2, 5)
        print(f'chunk2_rshift5{chunk2_rshift5}')
        ######## Split chunk 2 into chunk A and B #########
        len_chunkAB = chunks(chunk2_rshift5, 2)
        chunkA = chunk2_rshift5[:len_chunkAB]
        chunkB = chunk2_rshift5[len_chunkAB:]
        print(f'chunkA: {chunkA} \n chunkB: {chunkB}')

        ####### Right shift chunk A by 7 ########
        chunkA_rshift7 = shifta(chunkA, 7)
        ###### XOR Chunk B ###########
        chunkB_usable_key = key_length_op(chunkB, passwd_bin)
        chunkB_xored = xora(chunkB, chunkB_usable_key)
        print(f'chunkA_rshift7: {chunkA_rshift7} \n chunkB_xored: {chunkB_xored}')

        #########   CHUNK 1 ############
        ######### Reverse Chunk 1 #######
        chunk1_rvd = reversa(chunk1)
        ###### XOR chunk1_rvd ###########
        chunk1_rvd_usable_key = key_length_op(chunk1_rvd, passwd_bin)
        chunk1_rvd_xored = xora(chunk1_rvd, chunk1_rvd_usable_key)
        print(f'chunk1_rvd:  {chunk1_rvd} \n chunk1_rvd_xored: {chunk1_rvd_xored}')

        ######### Concatenate chunk A and 1
        cnct_2A_1 = chunk1_rvd_xored + chunkA_rshift7
        print("cnct_2A_1: ", cnct_2A_1)
        ############ XOR cnct_A_1 with key #########
        cnt_1_2A_usable_key = key_length_op(cnct_2A_1, passwd_bin)
        cnct_2A_1_xored = xora(cnct_2A_1, cnt_1_2A_usable_key)
        print("Chunk 1, 2A concat, XORED: ", cnct_2A_1_xored)

        ######### Concatenate all and INFO #########
        ciph = cnct_2A_1_xored + chunkB_xored
        ciph_txt_bits = ciph + len_pt
        print("Binary cipher text: ", ciph)
        cipher_text = hex(int(ciph_txt_bits, 2))
        print("CIPHER TEXT: ", cipher_text)
        return cipher_text  

    def decrypta(self, ct, passwd):
        passwd_bin = pass_2_key(passwd)
        ciph_txt_bin = bin(int(ct, 16))[2:]
        print("Cipher Text: ", ciph_txt_bin)
        infobits = ciph_txt_bin[len(ciph_txt_bin)-256:]
        # print("Info bits: {} -- {}".format(infobits, len(infobits)))
        plain_txt_len = int(infobits, 2)
        print("Plain text length: ", plain_txt_len)
        ciph_text_len = len(ciph_txt_bin)

        ciph_txt_bit = ciph_txt_bin[:(ciph_text_len - 256)]
        print("CT Bits: ", ciph_txt_bit)
        # do some padding
        ciph_txt_bit_pad = ciph_txt_bit.zfill(plain_txt_len)
        ciph_txt_bit_pad = ciph_txt_bit.zfill(plain_txt_len)
        print("Padded cipher text binary: ", ciph_txt_bit_pad)
        ######## obtain chunk cnct_2A_1_xored and chunkB_xored ######
        chunk_length = chunks(ciph_txt_bit_pad, 4)
        print("Length of Cipher text: ", len(ciph_txt_bit_pad))
        print("Chunk Lenhth: ", chunk_length)
        chunkB_xored = ciph_txt_bit_pad[(plain_txt_len-chunk_length):]
        cnct_2A_1_xored = ciph_txt_bit_pad[:plain_txt_len-chunk_length]
        print("Chunk cnct_2A_1_xored: ", cnct_2A_1_xored)
        print("Chunk B Xored: ", chunkB_xored)
        ######### UnXOR chunkB_xored ###############
        chunkB_xored_usable_key = key_length_op(chunkB_xored, passwd_bin)
        chunkB = xora(chunkB_xored, chunkB_xored_usable_key)
        print("Chunk B: ", chunkB)
        ######### UnXOR cnct_2A_1_xored ###############
        cnct_2A_1_xored_usable_key = key_length_op(cnct_2A_1_xored, passwd_bin)
        cnct_2A_1 = xora(cnct_2A_1_xored, cnct_2A_1_xored_usable_key)
        print("cnct_2A_1: ", cnct_2A_1)
        ############### Split cnct_2A_1 into chunk1_xored AND chunkA_rshift7chunkA_rshift7  ########
        chunkA_rshift7 = cnct_2A_1[len(cnct_2A_1)-chunk_length:]
        chunk1_rvd_xored = cnct_2A_1[:len(cnct_2A_1)-chunk_length]
        ############# XOR chunk1_xored ###############
        chunk1_rvd_xored_usable_key = key_length_op(chunk1_rvd_xored, passwd_bin)
        chunk1_rvd = xora(chunk1_rvd_xored, chunk1_rvd_xored_usable_key)
        chunk1 = reversa(chunk1_rvd)
        print(f'chunkA_rshift7: {chunkA_rshift7} \n chunk1_xored: {chunk1_rvd_xored} \n chunk1_rvd: {chunk1_rvd} \n chunk1: {chunk1}')
        ######### left shift chunkA_rshift7 ##############
        chunkA = shifta(chunkA_rshift7, -7)
        ############# concatenate chunkA and chunkB left shift by 5 ########
        chunk2_rshift5 = chunkA + chunkB
        chunk2 = shifta(chunk2_rshift5, -5)
        ############## Concatenate chunk2 and chunk1  ###########
        fin_plain_text_xored = chunk1 + chunk2
        fin_plain_text_xored_key = key_length_op(fin_plain_text_xored, passwd_bin)
        plain_txt_bin =xora(fin_plain_text_xored, fin_plain_text_xored_key)
        print(f'chunkA: {chunkA} \n chunk2: {chunk2} \nfin_plain_text_xored: {fin_plain_text_xored} \nplain_txt_bin: {plain_txt_bin}')
        # convert to text
        plain_text = int(plain_txt_bin, 2)
        message = binascii.unhexlify('%x' % plain_text)
        plain_text = message.decode("utf-8")
        print(f'Plain Text: {message} \nplain_text_utf8: {plain_text}')
        return plain_text


# if __name__ == "__main__":
#     Cliff()
