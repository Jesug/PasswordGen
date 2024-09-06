import random
import string

def generate_password (length = 12):
    alphanumeric = string.ascii_letters + string.punctuation + string.digits 
    gen_password = ''.join(random.choice(alphanumeric) for i in range (length))
    return gen_password


gen_password = generate_password()
print("Password: " + gen_password)
 
 