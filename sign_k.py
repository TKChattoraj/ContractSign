
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils, padding
from cryptography.hazmat.backends import default_backend
from cryptography import exceptions 
import os

# Titan and Charlie enter into a contract for a 
# dog bowl for 1BTC.  Titan is the seller and 
# Charlie is the buyer.

# class rsaKeys will hold a object for managng rsa keys
# managing: creating, storing, loading.
# Think about including encrypting, decrypting and signing.

class rsaKeys():
    def __init__(self, password=None, name=None):
        self.name = name       
        self.password = password
       
    def create_new_keys(self):
        self.priv_key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096)
        self.pub_key = self.priv_key.public_key()
        self.priv_key_pem = self.private_pem()
        self.pub_key_pem = self.pub_pem()
        self.save_key(True, self.priv_key_pem)
        self.save_key(False, self.pub_key_pem)

    def private_pem(self):
        pem=self.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.password)
        )
        return pem

    def pub_pem(self):
        pem=self.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return pem
    
    def save_key(self, private, pem):
        if private:
            path = r"./" + self.name+"_private.pem"    
        else:
            path = r"./"+self.name+"_public.pem"
        with open(path, "wb") as f:
                f.write(pem)
       
    def load_key_from_file(self, private):  
    # returns a <class 'cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey'>
    # <class 'cryptography.hazmat.backends.openssl.rsa._RSAPublicKey'> as applicable

        if private:
            path = r"./" + self.name+"_private.pem"
            with open(path, "rb") as f:
                return serialization.load_pem_private_key(
                    f.read(),
                    password=self.password,
                    backend=default_backend()
                )
        else:
            path = r"./"+self.name+"_public.pem"  
            with open(path, "rb") as f:
                return serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )


# get the contract to be signed

file_read=open(r"./dog_bowl_k_05-14-2022.txt", "r")
contract = file_read.read()
file_read.close()
print("contract: ")
print(contract)

# Contract string made into byte litteral using utf-8 encoding.
# The byte litteral is what will be encrypted, hashed-signed
contract_bytes = bytes(contract, 'utf-8')
print("Data after made into bytes")
print(contract_bytes)

#### encrypt the contract using RSA

# Charlie generates encryption and signature keys.
# c means "Charlie", e means "encryption", s means 
# "signature"
c_e_rsa = rsaKeys(b"password_ce", "cd_rsa")
c_e_rsa.create_new_keys()
print("c_e_rsa.pub_key_pem")
print(c_e_rsa.pub_key_pem)

# print("priv_key type")
# print(type(c_e_rsa.priv_key))
# print("pub_key type")
# print(type(c_e_rsa.pub_key))
# print("priv pem type")
# print(type(c_e_rsa.priv_key_pem))
# print("pub pem type")
# print(type(c_e_rsa.pub_key_pem))

# object types:
# c_e_rsa.priv_key: <class 'cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey'>
# c_e_rsa.pub_key: <class 'cryptography.hazmat.backends.openssl.rsa._RSAPublicKey'>
# c_e_rsa.priv_key_pem: <class 'bytes'>
# c_e_rsa.pub_key_pem: <class 'bytes'>

c_s_rsa=rsaKeys(b"password_cs", "cs_rsa")
c_s_rsa.create_new_keys()

# Titan generates encryption and signature keys.
t_e_rsa = rsaKeys(b"password_te", "te_rsa")
t_e_rsa.create_new_keys()

t_s_rsa=rsaKeys(b"passowrd_ts", "ts_rsa")
t_s_rsa.create_new_keys()


# Charlie sends public encryption key to Titan
# Titan receives public key
received_pub_pem=c_e_rsa.pub_key_pem
print("received pub_pem")
print(received_pub_pem)

# Titan create an rsaKeys object to hold and save Charlie's 
# pub key.  This actually should be done in a secure
# key ring (I think).
# r means "received".  It represents the key used by the
# other party. 
r_c_e_pub=rsaKeys(name='rce_rsa_pub')
r_c_e_pub.pub_key_pem=received_pub_pem
r_c_e_pub.save_key(private=False, pem=r_c_e_pub.pub_key_pem)

# Titan loads Charlie's pub key
# l means "load" from saved file
# The loaded pub key is of type: 
# <class 'cryptography.hazmat.backends.openssl.rsa._RSAPublicKey'>
l_c_e_pub=rsaKeys(name='rce_rsa_pub')
l_c_e_pub.pub_key=l_c_e_pub.load_key_from_file(False)

# print("rt_c_e_pub.pub_key type")
# print(type(l_c_e_pub.pub_key))
# print("rt_c_e_pub")
# print(l_c_e_pub.pub_pem())

# loaded and original Charlie pub keys the same?
print("Equal pub keys?")
print(l_c_e_pub.pub_pem() == c_e_rsa.pub_key_pem)

# Titan encrypts the contract and sends to Charlie
# Titan uses received and loaded Charlie pub key
e_contract = l_c_e_pub.pub_key.encrypt(
    contract_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Encrypted Contract")
print(e_contract)

# Titan sends encrypted contract and his encryption pub key to Charlie
# e_contract and t_e_rsa.pub_key_pem

# Charlie receives encrypted contract and Titan's pub key
# Charlie decrypts and reads and encrypts

# simulate receipt of encrypted contract and Titan pub key
received_e_k=e_contract
received_pub_pem=t_e_rsa.pub_key_pem
 
r_t_e_pub=rsaKeys(name='rte_rsa_pub')
r_t_e_pub.pub_key=serialization.load_pem_public_key(received_pub_pem, backend=default_backend())
r_t_e_pub.pub_key_pem=r_t_e_pub.pub_pem()
r_t_e_pub.save_key(private=False, pem=r_t_e_pub.pub_key_pem)


# Charlie uses his private encryption key to decrypt
d_contract=c_e_rsa.priv_key.decrypt(
    received_e_k,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# decrypted contract same as original
print("Decrypted?")
print(d_contract==contract_bytes)
d_contract_text=d_contract.decode('utf-8')
print(d_contract_text==contract)

print("Decrypted contract:")
print(type(d_contract_text))
print(type(contract))
print(d_contract_text)

# hash the contract for signature
# prepare the hash
chosen_hash = hashes.SHA256()
hasher = hashes.Hash(chosen_hash)
hasher.update(d_contract)
digest = hasher.finalize()  # digest for the hashed data

# Charlie uses his signature private key to sign the contract
charlie_sig = c_s_rsa.priv_key.sign(
    digest,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    utils.Prehashed(chosen_hash)
)

# Charlie uses received Titan's pub key to encrypt the contract

e_contract = r_t_e_pub.pub_key.encrypt(
    d_contract,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Encrypted Contract")
print(e_contract)

# Charlie sends encrypted contract, signature and signature pub key to Titan
# e_contract, charlie_sig, c_s_rsa.pub_key_pem

# Titan receives the encrypted contract, signature, encryption pub key from Charlie
received_e_k = e_contract
r_c_sig = charlie_sig
received_pub_pem=c_s_rsa.pub_key_pem

r_c_s_pub=rsaKeys(name='rcs_rsa_pub')
r_c_s_pub.pub_key=serialization.load_pem_public_key(received_pub_pem, backend=default_backend())
r_c_s_pub.pub_key_pem=r_c_s_pub.pub_pem()
r_c_s_pub.save_key(private=False, pem=r_c_s_pub.pub_key_pem)

# Titan decrypts the contract.  Is it the same he sent?


d_contract=t_e_rsa.priv_key.decrypt(
    received_e_k,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# decrypted contract same as original
print("Decrypted?")
print(d_contract==contract_bytes)
d_contract_text=d_contract.decode('utf-8')
print(d_contract_text==contract)

print("Decrypted contract:")
print(type(d_contract_text))
print(type(contract))
print(d_contract_text)

# Titan verifies Charlie's sig
# Use the hash prep from above
# Titan verifies with Charlie's pub key

# verify throws an InvalidSignature exception if not valid.
# Otherwise it returns None.
try:
    verified=r_c_s_pub.pub_key.verify(
    r_c_sig,
    d_contract,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

    print("Valid Signature")
except exceptions.InvalidSignature:
    print("Invalid Signature")



# ##### ECDSA #####

# ##### ECDSA Signature #####
# # generate ecdsa signature private key for use with SECP256K1 curve
# private_key = ec.generate_private_key(ec.SECP256K1)

# # sign the data--using the hash digest
# signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(chosen_hash)))

# print(signature)


# ##### ecdsa signature verification #####

# # signature public key:
# # this will need to be created and exported to the decrypter
# public_key = private_key. public_key()

# # decrypter will get the data and the signature together
# # need to hash the data received 

# data_decrypt = data
# #data_decrypt = data + b"!"


# hasher_decrypt = hashes.Hash(chosen_hash)
# hasher_decrypt.update(data_decrypt)
# digest_decrypt = hasher_decrypt.finalize()

# # the verification will throw an InvalidSignature exception if invalid
# # and return None if valid
# try:
#     valid_sig=public_key.verify(signature, digest_decrypt, ec.ECDSA(utils.Prehashed(chosen_hash)))
#     print("Valid Signature")

# except exceptions.InvalidSignature:
#     print("Invalid Signature")



