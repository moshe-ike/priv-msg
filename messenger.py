import os
import pickle
import string

from cryptography.hazmat.primitives import hashes, hmac
# from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography import exceptions
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pdb

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        # raise Exception("not implemented!")

        shared_key = self.server_decryption_key.exchange(ec.ECDH(),
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ct[1][16:]))
        hash = hmac.HMAC(shared_key, hashes.SHA256())
        
        hash.update(b"00")
        hash_copy = hash.copy()
        sym_key = hash_copy.finalize()
        hash.update(b"01")
        ad = hash.finalize()

        gcm = AESGCM(sym_key)
        # header = self.nonce + public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint), hashes.SHA256()
        ct = gcm.decrypt(ct[1][0:16], ct[0], ad)

        return pickle.loads(ct)


    def signCert(self, cert):
        # print(type(cert["public_key"]))
        data = pickle.dumps(cert)
        # chosen_hash = hashes.SHA256()
        # hasher = hashes.Hash(chosen_hash)
        # hasher.update(cert)
        # digest = hasher.finalize()
        # digest = DHPublicKey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        # print(type(digest))
        signature = self.server_signing_key.sign(data, ec.ECDSA(hashes.SHA256()))
        # raise Exception("not implemented!")
        return signature

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}
        self.nonce = os.urandom(16)
        self.CONSTANT = "fuck you. Don't take it personal I'm just tired"

    def generateCertificate(self):
        # raise Exception("not implemented!")
        # parameters = dh.generate_parameters(generator=2, key_size=2048)
        # client_private_key = parameters.generate_private_key()
        client_private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = client_private_key.public_key()
        self.private_key = client_private_key
        # cereal_key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        cereal_key = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        # print("type of serial: " + str(type(cereal_key)))


        return {"name": self.name, "public_key": cereal_key}

    def receiveCertificate(self, certificate, signature):
        # chosen_hash = hashes.SHA256()
        # hasher = hashes.Hash(chosen_hash)
        # hasher.update(certificate)
        # digest = hasher.finalize()
        data = pickle.dumps(certificate)

        try:
            self.server_signing_pk.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        except exceptions.InvalidSignature:
            raise Exception("signature failed")
        name = certificate["name"]
        self.certs[name] = certificate["public_key"]


    def sendMessage(self, name, message):
        if name not in self.conns:
            state = {}
            # parameters = ec.generate_parameters(generator=2, key_size=2048)
            # state["private_key"] = parameters.generate_private_key()
            state["private_key"] = ec.generate_private_key(ec.SECP256R1())
            state["dhs"] = state["private_key"].public_key()
            # print("first message")
            dhr = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), self.certs[name])
            state["dhr"] = dhr
            shared_key = state["private_key"].exchange(ec.ECDH(), dhr)

            # print(shared_key)

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=shared_key,
                info = shared_key,
                ).derive(pickle.dumps(self.CONSTANT))

            state["rk"] = derived_key[0:32]
            # print(state["rk"])

            state["cks"] = derived_key[32:]
            self.conns[name] = state
        # else:
        #     state = self.conns[name]
        #     # print(state)
        #     # parameters = ec.generate_parameters(generator=2, key_size=2048)
        #     state["private_key"] = ec.generate_private_key(ec.SECP256R1())
        #     state["dhs"] = state["private_key"].public_key()
        #     # print(state["dhs"])
        #     # print(state["private_key"])
        #     # print(state["dhs"])

        #     # if "dhr" not in state:
        #     #     # state["dhr"] = self.certs[name]
        #     #     state["dhr"] = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), self.certs[name])
            
        #     # public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), state["dhr"])

        #     # shared_key = state["private_key"].exchange(state["public_key"])
        #     shared_key = state["private_key"].exchange(ec.ECDH(), state["dhr"])

        #     # print(shared_key)
        #     # print(state["dhr"])

        #     # self.conns[name] = self.certs[name]
        #     # print(state["rk"])
        #     print("2nd time: " + str(shared_key))
        #     derived_key = HKDF(
        #         algorithm=hashes.SHA256(),
        #         length=64,
        #         salt=shared_key,
        #         info = state["rk"]
        #         ).derive(pickle.dumps(self.CONSTANT))
        #     state["rk"] = derived_key[0:32]
        #     # print("send msg again: " + str(state["rk"]))
        #     state["cks"] = derived_key[32:]
        #     self.conns[name] = state
            
        
        state = self.conns[name]

        hash = hmac.HMAC(state["cks"], hashes.SHA256())
        hash.update(b"00")
        hash_copy = hash.copy()
        state["cks"] = hash_copy.finalize()
        hash.update(b"01")
        message_key = hash.finalize()
        
        dhs_bytes = state["dhs"].public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        # print(dhs_bytes)
        # print(state["dhs"])
        # print("dhs: " + str(dhs_bytes))
        # nonce_byte = pickle.dumps(self.nonce)
        header = self.nonce + dhs_bytes 
        # print(state["dhs"])
        # print(dhs_bytes)
        gcm = AESGCM(message_key)
        # print("msg key: " + str(message_key))
        ct = gcm.encrypt(self.nonce, pickle.dumps(message), header)
        
        # nonce_number = int.from_bytes(self.nonce, "big") + 1
        # self.nonce = pickle.dumps(nonce_number)
        self.conns[name] = state
        # print("sending msg")
        # pdb.set_trace()
        return header, ct
        
        # return ratchetEncrypt(name, message)
        
    # def ratchetEncrypt(self, name, plaintext):
    #     state = self.conns[name]

    #     hash = hmac.HMAC(state["cks"], hashes.SHA256())
    #     hash.update(b"00")
    #     hash_copy = hash.copy()
    #     state["cks"] = hash_copy.finalize()
    #     hash.update(b"01")
    #     message_key = hash.finalize()
        
    #     dhs_bytes = state["dhs"].public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    #     nonce_byte = int.from_bytes(self.nonce, "big")
    #     header = nonce_byte + dhs_bytes
    #     gcm = AESGCM(message_key)
    #     ct = gcm.encrypt(nonce_byte, plaintext, header)
        
    #     self.nonce = self.nonce + 1
    #     self.conns[name] = state
    #     return header, ct
                

    def receiveMessage(self, name, header, ciphertext):
        # raise Exception("not implemented!")
        #header has public key of sender
        # secret key from last message i sent/in certificate
        # 
        # import pdb;#pdb.set_trace()
        if name not in self.conns:
            state = {}
            dhr_bytes = header[16:]
            # state["dhr"] = header[16:]
            state["dhr"] = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dhr_bytes)
            # print("dhr: " + str(state["dhr"]))
            # state["dhr"] = header
            # public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), state["dhr"])
            # shared_key = self.private_key.exchange(ec.ECDH(), state["dhr"])

            shared_key = self.private_key.exchange(ec.ECDH(), state["dhr"])

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=shared_key,
                info = shared_key
                ).derive(pickle.dumps(self.CONSTANT))
            state["rk"] = derived_key[0:32]
            # print(state["rk"])
            state["ckr"] = derived_key[32:]

            # parameters = ec.generate_parameters(generator=2, key_size=2048)
            # state["private_key"] = parameters.generate_private_key()
            state["private_key"] = ec.generate_private_key(ec.SECP256R1())
            state["dhs"] = state["private_key"].public_key()
            # public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), state["dhr"])
            # shared_key = state["private_key"].exchange(ec.ECDH(), public_key)
            shared_key = state["private_key"].exchange(ec.ECDH(), state["dhr"])


            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=shared_key,
                info = state["rk"]
                ).derive(pickle.dumps(self.CONSTANT))

            state["rk"] = derived_key[0:32]
            # print(state["rk"])

            state["cks"] = derived_key[32:]
            self.conns[name] = state
            # print("received msg from stranger")
            # pdb.set_trace()
        elif header[16:] != self.conns[name]["dhr"].public_bytes(Encoding.X962, PublicFormat.CompressedPoint):
            # pdb.set_trace()
            # print("dh ratchet")
            # pdb.set_trace()

            # print(header)
            # print(self.conns)
            state = self.conns[name]
            dhr_bytes = header[16:]
            # state["dhr"] = header[16:]
            state["dhr"] = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dhr_bytes)
            # print(state["dhr"])
            # print("dhr: " + str(state["dhr"]))

            # print(state["dhr"])
            # pub_key = state["dhr"].public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
            # print(pub_key)
            # shared_key = state["private_key"].exchange(state["dhr"])
            shared_key = state["private_key"].exchange(ec.ECDH(), state["dhr"])

            # print("2nd time: " + str(shared_key))
            # print(state["rk"])

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=shared_key,
                info = state["rk"]
                ).derive(pickle.dumps(self.CONSTANT))
            state["rk"] = derived_key[0:32]
            # print(state["rk"])
            state["ckr"] = derived_key[32:]


            # parameters = ec.generate_parameters(generator=2, key_size=2048)
            state["private_key"] = ec.generate_private_key(ec.SECP256R1())
            state["dhs"] = state["private_key"].public_key()

            # public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), state["dhr"])
            # shared_key = state["private_key"].exchange(ec.ECDH(), public_key)

            # shared_key = state["dhs"].exchange(ec.ECDH(), state["dhr"])

            # shared_key = state["dhs"].exchange(ec.ECDH(), public_key)
            shared_key = state["private_key"].exchange(ec.ECDH(), state["dhr"])


            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=shared_key,
                info = state["rk"]
                ).derive(pickle.dumps(self.CONSTANT))

            state["rk"] = derived_key[0:32]
            state["cks"] = derived_key[32:]
            self.conns[name] = state

            # state.CKr, mk = KDF_CK(state.CKr)  
            # return ratchetDecrypt(name, ciphertext)
            # print("end of ratchet")
            # pdb.set_trace()
        
        state = self.conns[name]
        hash = hmac.HMAC(state["ckr"], hashes.SHA256())
        hash.update(b"00")
        hash_copy = hash.copy()
        state["ckr"] = hash_copy.finalize()
        hash.update(b"01")
        message_key = hash.finalize()
        # print("2nd rec msg key: " + str(message_key))
        gcm = AESGCM(message_key)

        try:
            plain = gcm.decrypt(header[0:16], ciphertext, header)
        except:
            return None

        return pickle.loads(plain)
    
    # def ratchetDecrypt(self, name, ciphertext):
    #     state = self.conns[name]
    #     hash = hmac.HMAC(state["cks"], hashes.SHA256())
    #     hash.update(b"00")
    #     hash_copy = hash.copy()
    #     state["cks"] = hash_copy.finalize()
    #     hash.update(b"01")
    #     message_key = hash.finalize()

            
        return

    def report(self, name, message):
        # raise Exception("not implemented!")
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        shared_key = private_key.exchange(ec.ECDH(), self.server_encryption_pk)
        hash = hmac.HMAC(shared_key, hashes.SHA256())
        
        hash.update(b"00")
        hash_copy = hash.copy()
        sym_key = hash_copy.finalize()
        hash.update(b"01")
        ad = hash.finalize()

        enc = name + ": " + message
        gcm = AESGCM(sym_key)
        # header = self.nonce + public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        # header = self.nonce + ad
        public_key_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

        ct = gcm.encrypt(self.nonce, pickle.dumps(enc), ad)

        return enc, [ct, self.nonce + public_key_bytes]
