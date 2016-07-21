#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import nacl.secret
import nacl.utils
import argparse
import binascii
import ast
from binascii import unhexlify
import etcd
import json
import os
import os.path
import random
import sys
import traceback
from OpenSSL.crypto import FILETYPE_PEM, load_certificate

kv_prefix = os.environ.get('PREFIX','vulcand')

def createParser ():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers (dest='command')
    subparsers.add_parser ('new_key')

    seal_keypair_parser = subparsers.add_parser ('seal_keypair')
    seal_keypair_parser.add_argument("-cert", help="Path to a certificate")
    seal_keypair_parser.add_argument("-privateKey", help="Path to a private key")
    seal_keypair_parser.add_argument("-sealKey", help="Seal key - used to encrypt and seal certificate and private key")

    open_keypair_parser = subparsers.add_parser ('open_keypair')
    open_keypair_parser.add_argument("-cn", help="Certificate CN")
    open_keypair_parser.add_argument("-dir", help="Path to a key/cert pair")
    open_keypair_parser.add_argument("-sealKey", help="Seal key - used to encrypt and seal certificate and private key")
    return parser


def new_seal_key():
    return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)


def hexlify(bytes):
    return binascii.hexlify(bytes).decode()


def cert_get_cn(file):
    return load_certificate(FILETYPE_PEM, open(file).read()).get_subject().CN


def etcd_connect(etcd_endpoints):
    try:
        client = etcd.Client(**random.choice(etcd_endpoints))
        client.get("/")
        return client
    except etcd.EtcdException as e:
        print("Exception in user code:")
        print("-"*60)
        traceback.print_exc(file=sys.stdout)
        print("-"*60)


if __name__ == '__main__':
    parser = createParser()
    namespace = parser.parse_args(sys.argv[1:])

    try:
        etcd_endpoints = [{
            'protocol': endpoint.split(':')[0],
            'host': endpoint.split(':')[1],
            'port': int(endpoint.split(':')[2]),
        } for endpoint in os.environ['ETCDCTL_PEERS'].replace('/','').split(',')]
        if namespace.command != "new_key":
            sealKey = namespace.sealKey if namespace.sealKey else os.environ['SEALKEY']
        else:
            sealKey = None
    except KeyError as e:
        print("%s: variable is not set" % e.args, file=sys.stderr)
        sys.exit(127)

    #print (namespace)

    if namespace.command == "new_key":
        print("%s" % hexlify(new_seal_key()))
    elif namespace.command == "seal_keypair":
        cli = etcd_connect(etcd_endpoints)
        cn = cert_get_cn(namespace.cert)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        box = nacl.secret.SecretBox(unhexlify(sealKey))
        key_pair = json.dumps({"crt": open(namespace.cert).read(), "key": open(namespace.privateKey).read()}).encode()
        cli.set('/{prefix}/cert/{cn}/host'.format(prefix=kv_prefix, cn=cn),{"Name": cn, "Nonce": hexlify(nonce), "Payload": hexlify(box.encrypt(key_pair, nonce))})
    elif namespace.command == "open_keypair":
        cli = etcd_connect(etcd_endpoints)
        box = nacl.secret.SecretBox(unhexlify(sealKey))
        try:
            for record in cli.read('/{prefix}/cert'.format(prefix=kv_prefix), recursive=True).children:
                if record.value:
                    data = ast.literal_eval(record.value)
                    key_pair = box.decrypt(unhexlify(data['Payload']))
                    with open(os.path.join(namespace.dir,"%s.crt" % data['Name']), 'w', encoding='latin-1') as f:
                        f.write(json.loads(key_pair.decode())['crt'])
                    with open(os.path.join(namespace.dir,"%s.key" % data['Name']), 'w', encoding='latin-1') as f:
                        f.write(json.loads(key_pair.decode())['key'])
        except etcd.EtcdKeyNotFound as e:
            pass

