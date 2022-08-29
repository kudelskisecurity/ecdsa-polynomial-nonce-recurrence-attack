# ECDSA polynomial nonce recurrence attack

[![Sagemath 9.6+](https://img.shields.io/badge/sagemath-9.6+-blue.svg)](https://www.sagemath.org/index.html) [![License: GPL v3](https://img.shields.io/badge/license-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)


This is a multithreaded implementation of the polynomial nonce recurrence attack on ECDSA.

# What's in this repository?

In this repository, you will find the following.

In the `attacks` directory: multithreaded implementation of the attack for Bitcoin, Ethereum and TLS,
to be used with inputs produced by 
[ecdsa-dump-bitcoin](https://github.com/kudelskisecurity/ecdsa-dump-bitcoin),
[ecdsa-dump-ethereum](https://github.com/kudelskisecurity/ecdsa-dump-ethereum) and 
[ecdsa-dump-tls](https://github.com/kudelskisecurity/ecdsa-dump-tls)
respectively.
Note that the dump files must have been sorted by public key, and then by timestamp so that the attack works.

In the `original-attack` folder, we provide the original (easy to read) proof-of-concept of the attack.
The one that was later used in production is the `recurrence_nonce` attack.

# Requirements

* [Sagemath](https://www.sagemath.org/) 9.6+

# Installation

First, install [sagemath](https://www.sagemath.org/) for your platform.
For example, on Arch Linux:

```
sudo pacman -S sagemath
```

Then install the required python libraries within the sage environment:

```
sage -pip install -r requirements.txt
```

# Usage

## Proof-of-concept

```
cd original-attack/
./recurrence_nonces.py
```

## Bitcoin attack

### Example

First obtain a dump using [ecdsa-dump-bitcoin](https://github.com/kudelskisecurity/ecdsa-dump-bitcoin).
The input file must have the following format:

```
r;s;pubkey;txid;message_hash;block_time
```

Then sort the dump by public key and then by timestamp (sort by field 3 and then 6):

```
sort bitcoin-input.csv --parallel=16 -T /path/to/tmp/ --field-separator ';' --buffer-size="70%" -k3,3 -k6,6 > sorted-bitcoin-input.csv
```

Finally, run the attack on the sorted file:

```
./attacks/ecdsa_bitcoin_attack.py -i sorted-input.csv -o bitcoin-attack-results.csv
```

The output file will contain, on each line (assuming N=4):

```
d;pubkey;first_txid;batch_size;pubkey_address;r1;r2;r3;r4;s1;s2;s3;s4;hash1;hash2;hash3;hash4;k1;k2;k3;k4;block_time1;block_time2;block_time3;block_time4"
```

Where:

* `d` is the private key
* `r1` to `rN` are the ECDSA signature `r` values for each signature in the window where the attack worked
* `s1` to `sN` are the ECDSA signature `s` values for each signature in the window where the attack worked
* `k1` to `kN` are the recovered ECDSA nonces for each signature in the window where the attack worked
* The other values' names are self-explanatory

## Ethereum attack

### Example

First obtain a dump using [ecdsa-dump-ethereum](https://github.com/kudelskisecurity/ecdsa-dump-ethereum).
The input file must have the following format:

```
from_address;r;s;pubkey;txid;message_hash;block_time
```

Then sort the dump by public key and then by timestamp (sort by field 4 and then 7):

```
time sort ethereum-input.csv --parallel=16 -T /path/to/tmp/ --field-separator ';' --buffer-size="70%" -k4,4 -k7,7 > sorted-ethereum-input.csv
```

Finally, run the attack on the sorted file:

```
./attacks/ecdsa_ethereum_attack.py -i sorted-ethereum-input.csv -o ethereum-attack-results.csv
```

The output file will contain, on each line:

```
d;pubkey;first_txid;batch_size;pubkey_address;r1;r2;r3;r4;s1;s2;s3;s4;hash1;hash2;hash3;hash4;k1;k2;k3;k4;block_time1;block_time2;block_time3;block_time4"
```

Where:

* `d` is the private key
* `r1` to `rN` are the ECDSA signature `r` values for each signature in the window where the attack worked
* `s1` to `sN` are the ECDSA signature `s` values for each signature in the window where the attack worked
* `k1` to `kN` are the recovered ECDSA nonces for each signature in the window where the attack worked
* The other values' names are self-explanatory

## TLS attack

### Example

First obtain a dump using [ecdsa-dump-tls](https://github.com/kudelskisecurity/ecdsa-dump-tls).
The input file must have the following format:

```
r;s;signature_value_hex;pubkey_hex;src_addr;server_name;msg_hex;timestamp

```

Then sort the dump by public key and then by timestamp (sort by field 4 and then 8):

```
time sort tls-input.csv --parallel=16 -T /path/to/tmp/ --field-separator ';' --buffer-size="70%" -k4,4 -k8,8 > sorted-tls-input.csv
```

Finally, run the attack on the sorted file:

```
./attacks/ecdsa_tls_attack.py -i sorted-tls-input.csv -o tls-attack-results.csv
```

The output file will contain, on each line (assuming N=4):

```
d;pubkey;server_name;batch_size;first_ip_address;r1;r2;r3;r4;s1;s2;s3;s4;hash1;hash2;hash3;hash4;k1;k2;k3;k4;timestamp1;timestamp2;timestamp3;timestamp4
```

Where:

* `d` is the private key
* `r1` to `rN` are the ECDSA signature `r` values for each signature in the window where the attack worked
* `s1` to `sN` are the ECDSA signature `s` values for each signature in the window where the attack worked
* `k1` to `kN` are the recovered ECDSA nonces for each signature in the window where the attack worked
* The other values' names are self-explanatory


## Show help

To display the full help with all the options available, pass `--help` or `-h`:

```
$ ./attacks/ecdsa_tls_attack.py --help
usage: ecdsa-tls-attack [-h] --input INPUT_PATH --output OUTPUT_PATH [-n N] [--max-futures MAX_FUTURES] [--no-sliding-window]

Run the polynomial nonce recurrence attack on a TLS dataset.

options:
  -h, --help            show this help message and exit
  --input INPUT_PATH, -i INPUT_PATH
                        Path to the input file. Must be a dump file in the format produced by ecdsa-dump-tls and which has been sorted by public key and then by timestamp.
  --output OUTPUT_PATH, -o OUTPUT_PATH
                        Path to the output file to dump to
  -n N                  Number of signatures per batch. N must be >= 4
  --max-futures MAX_FUTURES
                        Maximum number of futures to process in a batch. Increase this number if more cores are available.
  --no-sliding-window   Do not use a sliding window.Only use the first N signatures of each pubkey and discard the rest.Note that this will run faster but some vulnerable signatures may remain undetected
```

# License and Copyright

Copyright(c) 2023 Nagravision SA.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
License version 3 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not,
see http://www.gnu.org/licenses/.
