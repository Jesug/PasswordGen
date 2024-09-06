import string
import secrets
import hashlib
import hmac
import bcrypt

#FUNCTION FOR  RANDOMLY GENERATED PASSWORD
def generate_password (length = 12):
    alphanumeric = string.ascii_letters + string.punctuation + string.digits 
    gen_password = ''.join(secrets.choice(alphanumeric) for i in range (length))
    return gen_password


#FUNCTION FOR GENERATING RANDOM SALT
def generate_random_salt():
    return secrets.token_hex(16)


#FUNCTION FOR SHA256 HASH PASSWORD --- FIRST ALGORITHM
def generate_password_sha256 (gen_password, salt):
    h = hashlib.new("SHA256")
    h.update((gen_password + salt).encode())
    hash_password = h.hexdigest()
    return hash_password


#FUNCTION FOR MD5 HASH PASSWORD --- SECOND ALGORITHM
def generate_password_md5 (gen_password, salt):
    hash = hashlib.new("md5")
    hash.update((gen_password + salt).encode())
    hashed = hash.hexdigest()
    return hashed

#FUNCTION FOR HMAC HASH PASSWORD --- THIRD ALGORITHM
def generate_password_hmac (gen_password, salt):
    gen_password = bytes(gen_password, "utf-8")
    salt = bytes(salt, "utf-8")
    dig = hmac.new(gen_password, salt, hashlib.sha256)
    return dig.hexdigest()


#FUNCTION FOR BCRYPT HASH PASSWORD --- FOURTH ALGORITHM
def generate_password_bcrypt (gen_password):
    salting = bcrypt.gensalt()
    hashed = bcrypt.hashpw(gen_password.encode('utf-8'), salting)
    return hashed


#PRINTING AND FUNCTION CALL
gen_password = generate_password()
salt = generate_random_salt()
print(f"SALT: {salt}\n") 

print(f"RANDOMLY GENERATED PASSWORD: {gen_password}\n") 

print(f"MD5 HASH: {generate_password_md5(gen_password, salt)}\n")

print(f"SHA256 HASH: {generate_password_sha256(gen_password, salt)}\n")

print(f"HMAC HASH: {generate_password_hmac(gen_password, salt)}\n")

print(f"BCRYPT HASH: {generate_password_bcrypt(gen_password)}")




 
 