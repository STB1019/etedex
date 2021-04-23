#! /bin/env python3
from getpass import getpass

import tinyec.ec
from Crypto.Util.Padding import pad, unpad
from tinyec import registry
import secrets
import socket
from threading import Thread
from Crypto.Cipher import AES
import argparse
from pathlib import Path
import gnupg
import platform

IP = "178.128.200.134"
PORT = 6073
VERBOSE = False
GNUPG_HOME = str(Path.home()) + "/.gnupg" if platform.system() != "Windows" else "%APPDATA%/.gnupg" #TODO HELP, DUNNO WHAT DIRECTORY ON WINDOWS

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='etedex')
    parser.add_argument("-i", "--ip", dest='ip',
                        help="specify the ip", type=str)
    parser.add_argument("-p", dest='psw',
                        help="specify the password", type=int)
    parser.add_argument("-v", "--verbose", dest='verbose',
                        help="verbose output", action='store_true')
    parser.add_argument("-g", "--gpg-home", dest='gpg_home',
                        help="specify gpg home", type=str)
    parser.add_argument("-k", "--gpg-key", dest='gpg_key',
                        help="specify gpg key to use", type=str)
    parser.add_argument("-c", "--connect", dest='wanted_fingerprint',
                        help="specify user to connect to", type=str)

    args = parser.parse_args()
    if args.ip: IP = args.ip
    if args.verbose: VERBOSE = args.verbose
    if args.gpg_home: GPG_HOME = args.gpg_home

    print("loading the private key from the host system")
    gpg = gnupg.GPG(gnupghome=GNUPG_HOME)
    gpg.verbose = VERBOSE
    gpg.encoding = 'utf-8'

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((IP, PORT))

    client.send(args.gpg_key.encode()) #whoami
    client.send(args.wanted_fingerprint.encode()) #wo i want to talk with

    #public key exchange
    client.send(gpg.export_keys(args.gpg_key, False, armor=True)) #my public key
    oth_public_key = client.recv(4096)

    #check if fingerprint is equal to wanted
    with open("tmp", "w") as tmp_file:
        tmp_file.write(oth_public_key.decode())

    temp_key_data = gpg.scan_keys("tmp")

    if temp_key_data.fingerprint != args.wanted_fingerprint:
        raise "NOT THE ONE I WANTED " + temp_key_data.fingerprint + " " + args.wanted_fingerprint



    # #scan and get fingerptint, if already trusted, then not add, or else ask for addition as below
    #
    # import_result = gpg.import_keys("""-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmJMEYIKRBxMJKyQDAwIIAQENBAMEciPxOhZeWqkgs0Zj7US64urfbPkSJ/VdzZ1u\nPtBWUDHzFwYNa7gLMpGSsMMvDCOIB0Z0LGnGEU9omD4TDQV5lCiS9LCGNcWjEEsI\nyW6Izgw3hDCaQl6AZps8F/83Qr/LvHxpPdEpCmrzF7Ish4jciH5P0UdLjKii73GW\nJyN0GZG0NkVucmljbyBCcmFtYmlsbGEgRUNDIChFQ0MpIDxlbnJpYy5icmFtYmls\nbGFAZ21haWwuY29tPojQBBMTCgA4FiEEC1Sd1z9Fm/68tQ5tQr1CMQvwB60FAmCC\nkQcCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQQr1CMQvwB60a4QIAlCuG\nLjkf2KusNuaY/vK+k3WGusGUGTLrKqJcqq2yLuMtuBUQmZd1h6mKPAEkTqC/SAHK\n8+We8bwU6hferM/xQQH/QRz78SZOt1Ry0Bb3FsXmvj4S/xAE+WhOzLMNIxrUFSy5\nBugAGbbyMf9T4bAJrP5seKohDJ9joovRRNDhS/sx0biXBGCCkQcSCSskAwMCCAEB\nDQQDBCJ9rzhPm65QZ1EYf7OocOhn0vaPLr9u30KWiSB8BoOjIPmn7JsDTd57zyZB\n0bDJKJWDYq+/CBdZq3dNCScZdT4DFccSRdl5KtuFy8YP+82Spsos01MsmwrYAn59\nuWZrhSnQrpr3MxZzSnqYgkf5me0FaZYVLafdpTfanVk6bfFWAwEKCYi4BBgTCgAg\nFiEEC1Sd1z9Fm/68tQ5tQr1CMQvwB60FAmCCkQcCGwwACgkQQr1CMQvwB63VVQH8\nCheOmZZyNgAzmZH8KCv9ymO3G8GCeUDHYaPzfk9foXL2/bGP3UOJRy8mtGtJfuwf\n0EavfYXMctpHMZsj4dlgjwIAhP3GCs2RWvVOQARnJIO3mSIoC7XLqweHMtvoiAWI\nuuoAA60FpSwQi17Q++mBeII+U+Phf7035CK0/qjHcdJ+wg==\n=7bYS\n-----END PGP PUBLIC KEY BLOCK-----""")
    # gpg.trust_keys(import_result.fingerprints, "TRUST_FULLY")
    #
    # print(gpg.export_keys(GPG_KEY, True, passphrase=getpass(prompt='Password: ', stream=None), armor=False))
    # print(gpg.export_keys(import_result.fingerprints[0], False, armor=False))