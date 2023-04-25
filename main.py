import hashlib
import json
from base64 import b64decode, b64encode

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


class TrustWallet:
    scrypt_config = dict(n=2**14, r=8, p=1, dklen=32)
    mode = AES.MODE_GCM

    @staticmethod
    def encrypt(plain_text: str, password: str) -> dict:
        """
        Notes on encrypt() function
        Nonce: A random nonce (arbitrary value) must be a random and unique value for each time our encryption function is used with the same key. Think of it as a random salt for a cipher. The library supplies us with a secure nonce.
        Scrypt: Scrypt is used to generate a secure private key from the password. This will make it harder for an attacker to brute-force our encryption.
        Salt: A new random salt is used for each run of our encryption. This makes it impossible for an attacker to use precomputed hashes in an attempt to crack the cipher. (see rainbow table)
        Scrypt parameters:
        N is the cost factor. It must be a power of two, and the higher it is the more secure the key, but the more resources it requires to run.
        R is the block size.
        P is the parallelization factor, useful for running on multiple cores.
        Base64: We encode all of our bytes-type data into base64 a convenient string representation
        Tag (MAC): The tag is used to authenticate the data when using AES in GCM mode. This ensures no one can change our data without us knowing about it when we decrypt.
        """
        salt = get_random_bytes(AES.block_size)

        private_key = hashlib.scrypt(
            password.encode(), salt=salt, **TrustWallet.scrypt_config
        )
        cipher_config = AES.new(private_key, TrustWallet.mode)

        cipher_text, tag = cipher_config.encrypt_and_digest(
            bytes(plain_text, "utf-8"),
        )
        return {
            "cipher_text": b64encode(cipher_text).decode("utf-8"),
            "salt": b64encode(salt).decode("utf-8"),
            "nonce": b64encode(cipher_config.nonce).decode("utf-8"),
            "tag": b64encode(tag).decode("utf-8"),
        }

    @staticmethod
    def decrypt(encode_config: str, password: str) -> str:
        """
        The decrypt() function needs the same salt, nonce, and tag that we used for encryption. We used a dictionary for convenience in parsing, but if we instead wanted one string of ciphertext we could have used a scheme like salt.nonce.tag.cipher_text
        The configuration parameters on the Scrypt and AES functions need to be the same as the encrypt function.
        """
        enc_config: dict = json.loads(encode_config)
        salt: bytes = b64decode(enc_config["salt"])
        cipher_text: bytes = b64decode(enc_config["cipher_text"])
        nonce: bytes = b64decode(enc_config["nonce"])
        tag: bytes = b64decode(enc_config["tag"])

        private_key = hashlib.scrypt(
            password.encode(), salt=salt, **TrustWallet.scrypt_config
        )
        cipher = AES.new(private_key, TrustWallet.mode, nonce=nonce)

        decrypted_data: bytes = cipher.decrypt_and_verify(cipher_text, tag)
        return decrypted_data.decode("utf-8")


if __name__ == "__main__":
    mode = int(input("Введите режим работы, где 1 - создание конфига, 2 - расшифровка конфига\n"))
    if mode == 1:
        plain_text: str = input("Введите текст для шифрования:\n")
        password: str = input("Введите пароль:\n")

        aes_config: dict = TrustWallet.encrypt(plain_text=plain_text, password=password)
        print('-----------Скопируйте-----')
        print(json.dumps(aes_config))
        print('--------------------------')
        input('\nДля выхода введите любой символ + enter или закройте программу')
        exit()

    if mode == 2:
        encode_config: str = input("Введите строку конфигурация декрипта:\n")
        password: str = input("Введите пароль:\n")

        decrypted_str: str = TrustWallet.decrypt(
            encode_config=encode_config, password=password
        )
        print('----Дешифрованная строка--')
        print(decrypted_str)
        print('--------------------------')
        input('\nДля выхода введите любой символ + enter или закройте программу')
        exit()
