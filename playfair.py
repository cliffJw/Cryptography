import string
key=input("Enter key: ")
msg=input("Eneter the Message: ")
key=key.upper().replace(' ', '')
unique_key = []
for i in key:
    if i not in unique_key:
        unique_key.append(i)
        
my_map = [i for i in unique_key]
for x in string.ascii_uppercase:
    if x not in my_map: 
        my_map.append(x)

ciphtxt =[]
plaintxt = []
msg = msg.upper().replace(' ', '')
for x in msg: 
    ciphtxt.append(my_map[25-my_map.index(x)])
for i in ciphtxt:
    plaintxt.append(my_map[25-my_map.index(i)])

print(''.join(map(str, my_map)))
print("The Ciphertext is: " + ''.join(map(str, ciphtxt)))
print("The decrypted messsage is: " + ''.join(map(str, plaintxt)))