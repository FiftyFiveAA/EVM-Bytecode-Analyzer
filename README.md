# EVM-Bytecode-Analyzer

## Overview

**EVM Bytecode Analyzer** is a python implementation of the Ethereum Virtual Machine. It is intended to provide an easy way to debug and find vulnerabilities in smart contracts.

The code consists of python scripts as described in the data flow diagram below.

This project would not have been possible without the great work of others in the community. The following resources were leveraged during development.
* https://www.evm.codes/?fork=merge
* https://github.com/volcano852/pyevm/tree/ea9f558011765400875ca891b25d21a7f03752d0
* https://ethervm.io/
* https://ethereum.github.io/yellowpaper/paper.pdf
* https://github.com/ethereum/py-evm
* https://github.com/ethereum/go-ethereum

### Installation

* Install python 3.* , but not 3.11. As of writing this the python web3 library is not yet compatible with python 3.11.

```
python3 -m pip install web3, requests, binascii, hashlib, threading, json
```

## Guide/Additional Notes

## Data Flow Diagram

![image](https://user-images.githubusercontent.com/90160593/226202901-5773466b-716e-4589-9100-0ec6d9dff384.png)

## Software Bill of Materials

Python 3rd party libs

* http.server
* threading
* requests
* json
* web3
* binascii
* hashlib
