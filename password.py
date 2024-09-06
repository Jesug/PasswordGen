import random
import string

def generate_password (length = 12):
    alphanumeric = string.ascii_letters + string.punctuation + string.digits 
    password = ''.join(random.choice(alphanumeric) for i in range (length))
    return password


password = generate_password()
print("Generated Password: " + password)
 