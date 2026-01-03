# mongobleed

[CVE-2025-14847](https://github.com/advisories/GHSA-4742-mr57-2r9j) exploit for MongoDB heap memory disclosure via OP_COMPRESSED buffer over-read.

## Usage

```bash
$ bundle install
$ bundle exec ruby mongobleed.rb --host <target> --port 27017
```

## Context

Exploits insufficient validation of `uncompressed_size` in MongoDB's `OP_COMPRESSED` handler. The BSON parser reads beyond message boundaries into heap memory, leaking data through error messages.

Options: `--host`, `--port`, `--min-offset`, `--max-offset`, `--output`

## Disclaimer

For authorized security testing only. Based on research by Joe Desimone ([@dez_.](https://x.com/dez_))
