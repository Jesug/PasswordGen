import string
import secrets
import hashlib
import hmac
import bcrypt

#FUNCTION FOR  RANDOMLY GENERATED SECRETS PASSWORD
def generate_password (length = 12):
    alphanumeric = string.ascii_letters + string.punctuation + string.digits 
    gen_password = ''.join(secrets.choice(alphanumeric) for i in range (length))
    return gen_password


#FUNCTION FOR GENERATING RANDOM SALT
def generate_random_salt():
    return secrets.token_hex(16)


#FUNCTION FOR SHA256 + SALTED PASSWORD
def generate_password_sha256 (gen_password, salt):
    h = hashlib.new("SHA256")
    h.update((gen_password + salt).encode())
    hash_password = h.hexdigest()
    return hash_password


#FUNCTION FOR MD5 + SALTED PASSWORD
def generate_password_md5 (gen_password, salt):
    hash = hashlib.new("md5")
    hash.update((gen_password + salt).encode())
    hashed = hash.hexdigest()
    return hashed

#FUNCTION FOR HMAC + SALTED PASSWORD
def generate_password_hmac (gen_password, salt):
    gen_password = bytes(gen_password, "utf-8")
    salt = bytes(salt, "utf-8")
    dig = hmac.new(gen_password, salt, hashlib.sha256)
    return dig.hexdigest()


#FUNCTION FOR BCRYPT SALTED PASSWORD
def generate_password_bcrypt (gen_password):
    salting = bcrypt.gensalt()
    hashed = bcrypt.hashpw(gen_password.encode('utf-8'), salting)
    return hashed


#PRINTING AND FUNCTION CALL
gen_password = generate_password()
salt = generate_random_salt()
print(f"SALT: {salt}\n") 

print(f"RANDOMLY PASSWORD: {gen_password}\n") 

print(f"MD5 PASSWORD: {generate_password_md5(gen_password, salt)}\n")

print(f"SHA256 PASSWORD: {generate_password_sha256(gen_password, salt)}\n")

print(f"HMAC PASSWORD: {generate_password_hmac(gen_password, salt)}\n")

print(f"BCRYPT PASSWORD: {generate_password_bcrypt(gen_password)}")




 
 