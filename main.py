import binascii
from operator import ne
import re
from typing import Concatenate


########  OPERATION ON KEY #########
def key_length_op(chunk, key_bin):
    pt_chunk_len = len(chunk)
    key_len = len(key_bin)
    if key_len > pt_chunk_len:
        fin_key = key_bin[:pt_chunk_len]
    else:
        key_factor = int(pt_chunk_len/key_len) + 1
        fin_key = (key_bin*key_factor)[:pt_chunk_len]
        print("Expanded key: {} -- {}".format(fin_key, len(fin_key)))
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
    xored_data = (int(data_bin, 2) ^ int(key, 2))
    xored_data_bin = format(xored_data, 'b').zfill(len(data_bin))
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
    # def __init__(self):
    #     super(Cliff, self).__init__()

    #     text_input = input("Enter text: ")
    #     passwd = input("Enter password: ")

    #     # self.encrypta(text_input, passwd)
    #     self.decrypta(text_input, passwd)

    def encrypta(self, pt, encpasswd):
        ########### To BINARY CONVERSION #####
        plain_txt_bin = to_bin_convertor(pt)
        print("Binary plaintext: ", plain_txt_bin)
        passwd_bin = to_bin_convertor(encpasswd)
        # print("Binary password: ", passwd_bin)
        
        len_pt_bin = len(plain_txt_bin)
        print("PT Length UNPADED: ", len_pt_bin)
        new_plain_txt_bin = padding(plain_txt_bin, 4)
        len_new_pt_bin = len(new_plain_txt_bin)
        print("New PT bin:  ", new_plain_txt_bin)
        print("PT Binary Length:  ", len_new_pt_bin) 
        len_pt = '{0:08b}'.format(len_new_pt_bin).zfill(256) 
        print("final PT Binary Length:  ", len_pt)  
        # return cipher_text
###################      ENCRYPTION     #####################
        ############## XOR with key #################
        fin_key = key_length_op(new_plain_txt_bin, passwd_bin)
        fin_p_text_x_k = xora(new_plain_txt_bin, fin_key)
        print("XORed PT binary: ", fin_p_text_x_k)

        # divide pt into two equal chunks
        chunk_length = chunks(fin_p_text_x_k, 2)
        # print("Plain text bits: ", new_plain_txt_bin)
        chunk1 = new_plain_txt_bin[:chunk_length]
        print("Chunk 1 bits: ", chunk1)
        chunk2 = new_plain_txt_bin[chunk_length:]
        print("Chunk 2 bits: ", chunk2)
        ######### Right Shift Chunk 2 by 5 #########
        chunk2_rshift5 = shifta(chunk2, 5)
        ######## Split chunk 2 into chunk A and B #########
        len_chunkAB = chunks(chunk2_rshift5, 2)
        chunkA = chunk2_rshift5[:len_chunkAB]
        chunkB = chunk2_rshift5[len_chunkAB:]
        ####### Right shift chunk A by 7 ########
        chunkA_rshift7 = shifta(chunkA, 7)
        ###### XOR Chunk B ###########
        chunkB_usable_key = key_length_op(chunkB, passwd_bin)
        chunkB_xored = xora(chunkB, chunkB_usable_key)
        #########   CHUNK 1 ############
        ######### Reverse Chunk 1 #######
        chunk1_rvd = reversa(chunk1)
        print("chunk 1 reversed: ", chunk1_rvd)
        ###### XOR Chunk 1 ###########
        chunk1_usable_key = key_length_op(chunk1, passwd_bin)
        chunk1_xored = xora(chunk1, chunk1_usable_key)

        ######### Concatenate chunk A and 1
        cnct_2A_1 = chunk1_xored + chunkA_rshift7
        print("Concat of A and Chunk 1: ", cnct_2A_1)
        ############ XOR cnct_A_1 with key #########
        cnt_1_2A_usable_key = key_length_op(cnct_2A_1, passwd_bin)
        cnct_2A_1_xored = xora(cnct_2A_1, cnt_1_2A_usable_key)
        print("Chunk 1, 2A concat, XORED: ", cnct_2A_1_xored)

        ######### Concatenate all and INFO #########
        ciph_txt_bits = cnct_2A_1_xored + chunkB_xored + len_pt
        print("Binary cipher text: ", ciph_txt_bits)
        cipher_text = hex(int(ciph_txt_bits, 2))
        print("CIPHER TEXT: ", cipher_text)
        return cipher_text  

    def decrypta(self, ct, passwd):
        passwd_bin = to_bin_convertor(passwd)
        ciph_txt_bin = bin(int(ct, 16))[2:]
        # extract info
        infobits = ciph_txt_bin[len(ciph_txt_bin)-256:]
        print("Info bits: {} -- {}".format(infobits, len(infobits)))
        plain_txt_len = int(infobits, 2)
        print("Plain text length: ", plain_txt_len)

        ciph_txt_bit = ciph_txt_bin[:len(ciph_txt_bin) - 256]
        # do some padding
        ciph_txt_bit_pad = ciph_txt_bit.zfill(plain_txt_len)
        print("Padded cipher text binary: ", ciph_txt_bit_pad)
        
        ############ Determine Chunk Length ###########
        chunk_length = chunks(ciph_txt_bit_pad, 4)

        ########## obtain chunk 1 and chunk B ########
        chunk1 = ciph_txt_bit_pad[:plain_txt_len-chunk_length]
        chunkB = ciph_txt_bit_pad[plain_txt_len-chunk_length:]
        ###############  XOR Chunk B   ###################
        chunkB_usable_key = key_length_op(chunkB, passwd_bin)
        chunkB_xored = xora(chunkB, chunkB_usable_key)
        ##############  XOR Chunk 1 ######################
        chunk1_usable_key = key_length_op(chunk1, passwd_bin)
        chunk1_xored = xora(chunk1, chunk1_usable_key)
        ########## obtain chunk 1 and chunk A ########
        chunk1 = ciph_txt_bit_pad[:2*chunk_length]
        chunkA = ciph_txt_bit_pad[2*chunk_length:plain_txt_len-chunk_length]
        ####### Left shift chunk A by 7 ########
        chunkA_lshift7 = shifta(chunkA, -7)
        ################ Concatenate chunk A and B  #######
        chunk2 = chunkA_lshift7 + chunkB_xored
        ######### left Shift Chunk 2 by 5 #########
        chunk2_lshift5 = shifta(chunk2, -5)
        ######### Reverse Chunk 1 #######
        chunk1_rvd = reversa(chunk1)
        print("chunk 1 reversed: ", chunk1_rvd)
        ################ Concatenate chunk 1 and 2  #######
        plain_txt_bits = chunk1_rvd + chunk2_lshift5
        # convert to text
        plain_text = int(plain_txt_bits, 2)
        message = binascii.unhexlify('%x' % plain_text)
        print("Plain text", message)
        plain_text = message.decode("utf-8")
        return plain_text









# if __name__ == "__main__":
#     Cliff()
