from Crypto import Random
from Crypto.Cipher import AES

round_keys = []

def xor(a, b):
    a = '{:028b}'.format(int(a, 16))
    tmp = ''
    for i in range(len(a) - 1):
        tmp += str(int(a[i]) ^ int(b[i]))
    return tmp

def enc(card_number, rounds, produce_keys):

    encoded_number = '{:054b}'.format(int(card_number))
    l = encoded_number[:27]
    r = encoded_number[27:]

    if produce_keys:
        for i in range(rounds):
            # 16 bytes = 128 bits key length(AES128)
            key = Random.new().read(16)
            round_keys.append(key)

    for i in range(rounds):        
        
        key = round_keys[i]
        obj = AES.new(key)
        hex_r = '{:08x}'.format(int(r + '0'*5, 2))
        b = hex_r + '0'*23 + str(i+1)
        # only need 27 bits, so from 128 bit chipher will keep 28 bits
        enc_res = obj.encrypt(b.decode('hex')).encode('hex')[:7]
        tmp = r
        r = xor(enc_res, l)
        l = tmp

    return (l , r)

def dec(ciphertext, rounds):

    encoded_number = '{:054b}'.format(int(ciphertext))
    l = encoded_number[:27]
    r = encoded_number[27:]

    for i in range(rounds,0,-1):
        key = round_keys[i-1]
        obj = AES.new(key)
        
        hex_l = '{:08x}'.format(int(l + '0'*5, 2))
        b = hex_l + '0'*23 + str(i)
        enc_res = obj.encrypt(b.decode('hex')).encode('hex')[:7]
        tmp = l
        l = xor(enc_res, r)
        r = tmp

    return (l , r)

credit_card_number =  "7777777777777777"
print '\nNumber to encrypt - ' + credit_card_number

final_number = credit_card_number
while True:
    l, r = enc(final_number, 6, True)
    final_number = l + r
    final_number = int(final_number, 2)
    if final_number > 9999999999999999:
        print 'Not valid encrypted number - ' +  str(final_number)
    else:
        break

print 'Encrypted number - ' + str(final_number)
print 
print 'Decrypting ...'
print 
print 'Ciphertext to decrypt - ' + str(final_number)
while True:
    l, r = dec(final_number, 6)
    final_number = l + r
    final_number = int(final_number, 2)
    if final_number > 9999999999999999:
        print 'Not valid decrypted number - ' +  str(final_number)
    else:
        break
print 'Decrypted number - ' + str(final_number)
