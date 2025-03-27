import requests
import binascii

url = "https://t-capybit-kdot8z7j.spbctf.org/funds"
hex_origin1 = '28123600894ec0052e3afaf441dedcae4abdc27d3a8ed274650b81e03a739bb3e4ee6878480e466e79b7611d37acf917b7ab555caa7179c2139869894793dea65a16e22ea7051cdae18384c0c59d198d54d68dc04219a545c61acca4a3a07434b3b62e96a3ed5204389282ef542a1f80c4f2e5a63b5b40c6a072e109e86abc2a095e4610ec1f2eb6ed84aca7857006bbc7721aad77d3978c007acdb0f0510ddc8d41627093edaa3540fc1d9e03c7bbf8c9ed62693c9dab1f3f1c9e605b287880273f129c7f76c4a6445ccb3c10432ed219968f7e48488dd594816c864b'
hex_origin2 = '28123600894ec0052e3afae75ccfcffe0ff8812569ca972027188af17060d8edb9ba7b73591d022c2df4720026bfab4ae3fb160cf5232dd118896a9456809af91f55a66ce25149c9ea92c18381c9049c4783d981125ae019924589b7a8b16776e3eb7ad4b0a11e' 
hex_origin3 = '28123600894ec0052e3af9f742dddfad49bec17e398dd177660882e3397098b0e7ed6b7b4b0d456d7ab4621e34affa14b4a8565fa9727ac1109b6a8a4490dda55915e12da4061fd9e28087c3c69e1a8e57d58ec3411aa646c519cfa7a0a37737b0b52d95a0ee51073b9181ec57291c83c7f1e6a5385843c5a371e20aeb69bf290a5e4610ec1f2eb6ed84aca7857006bbc7721aad77d3978c007acdb0f0510ddc8d41627093edaa3540fc1d9e03c7bbf8c9ed62693c9dab1f3f1c9e605b287880273f129c7f76c4a6445ccb3c10432ed219968f7e48488dd594816c864b'
hex_origin4 = '28123600894ec0052e3abfa0039bdcbd57acd12d7fcb912c364fc4b4786090a2aefd2b26155a556568a4255f63efea0aa6b80701fe213a924cca3d9a4c82ddbb4b05a671e2465898a4d7d1d3ce8c5cce108290d1514cf104965989f8f7ff3127b8a73dd4f3b006462bdece'
hex_origin5 = '28123600894ec0052e3abfa0039bdfbd57acd12d7fcb912c364fc4b4786090a2aefd2b26155a556568a4255f63efea0aa6b80701fe213a924cca3d9a4c82ddbb4b05a671e2465898a4d7d1d3ce8c5cce108290d1514cf104965989f8f7ff3127b8a73dd4f3b006462bdece'

encrypted_data = bytes.fromhex(hex_origin1)
print(len(encrypted_data))
target_first_char = b'{"usr":"11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","*******************,"role":"user",********************************************************}'  # 72 (ASCII 'H')
test_key = bytearray(b'')
print(len(target_first_char))
m_l = len(encrypted_data)
for simb in range(0,m_l):
    for possible_key in range(256):  # Перебираем все возможные байты (0-255)
        decrypted_char = encrypted_data[simb] ^ possible_key
        if decrypted_char == target_first_char[simb]:
            print(f"{simb}  =   {possible_key} (0x{possible_key:02x})")
            test_key.append(possible_key)
            break
    else:
        print("{simb}  =   Ключ не найден")
print(test_key)
encrypted_data = bytes.fromhex(hex_origin2)
#key_test = bytearray(b'S0Do\xe5+\xfap]_\xcd\x82/')
test_origin = bytearray(b'')
m_l = len(encrypted_data)
for simb in range(0,m_l):
    decrypted_char = encrypted_data[simb] ^ test_key[simb]
    test_origin.append(decrypted_char)
print(test_origin.decode('utf-8'))

target_first_char = b'{"usern":"Monkey D Luffy", "attributes": {"role": "root", "clearance": 999, "untrusted": false, "department": "IT", "allow-flag": "yes"}}'
encrypted_data = bytearray(target_first_char)
key_test = bytearray(b'S0Cs\xec<\xae\'\x14\x18\xcb\xc5p\xef\xed\x9f{\x8c\xf3L\x0b\xbf\xe3ET:\xb0\xd1\x0bB\xaa\x82\xd5\xdfYIy?w_H\x86P,\x06\x9d\xc8&\x86\x9adm\x9b@H\xf3"\xa9X\xb8v\xa2\xef\x97k\'\xd3\x1f\x964-\xeb\xd0\xb2\xb5\xf1\xf4\xac(\xbce\xe7\xbc\xf1s(\x94t\xf7+\xfd\x95\x92\x91E\x05\x82\x87\x1f\xa7\x92\xdcc5\t\xa3\xb3\xdee\x1b.\xb1\xf5\xc3\xd4\x97\njq\xf7\x91C\xd08\xd9[\x8d\x1b8|j0\xce~Z\xc2\x9f\xed\xce\xd2\xf1\x15u\x99\xfdRa\x8f\x05\xbc\xfb\xe9"@\xed\x92\x85"h\xae\xafmBR\xf0\x81\xcfT2\x9ds\xfdf\xe5\x81\xd8\xfb\xc1BKI\xf3\xdfmJo\xea\x05?\nB\xa0SMg\xf9SV\xe6\xc2!,\xaaNd.K\xbcm\xb4\xb5^j;\xec\xb9\xf1\xf2N\xfb6')
test_origin = bytearray(b'')
m_l = len(encrypted_data)
for simb in range(0,m_l):
    decrypted_char = encrypted_data[simb] ^ key_test[simb]
    test_origin.append(decrypted_char)
session_c = {'session':test_origin.hex()}
print(session_c)
resp = requests.get('https://t-capybit-kdot8z7j.spbctf.org/funds',cookies = session_c)
print(resp.text)