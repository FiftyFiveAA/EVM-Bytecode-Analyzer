# EVM-Bytecode-Analyzer

## Overview

**EVM Bytecode Analyzer** is a disassembler/debugger for the Ethereum Virtual Machine (EVM). It includes a custom EVM implemented in python (evm_bytecode_analyzer.py & evm_instructions.py). This project is intended to provide an easy way to debug and find vulnerabilities in smart contracts.

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

### Usage

Most of the scripts in this repo can be ran on their own and will give you varying levels of access to the EVM internals we've implemented.

* **For those who want to interact directly with our EVM**

```
python3 evm_bytecode_analyzer.py
```

* **For those who would like to create their own frontend, add additional features, or just interact with an abstracted EVM: utilizing our API server is probably the way to go**
  - We have included an **openapi.yaml** file which you can open in various tools to see details about the available API endpoints.

```
python3 api_server.py
```

* **For those who would like to utilize our front end**

```
python3 evm.py
```

## Data Flow Diagram

![image](https://user-images.githubusercontent.com/90160593/226202901-5773466b-716e-4589-9100-0ec6d9dff384.png)

## API (api_server.py)

The API server makes it significantly easier to interact with the EVM without having to understand much of the internal code.

![image](https://user-images.githubusercontent.com/90160593/226477676-e88d4be8-493f-42db-a7c3-8853b2ab69da.png)

## Software Bill of Materials

Python 3rd party libs

* http.server
* threading
* requests
* json
* web3
* binascii
* hashlib

Javascript 3rd party libs

* jquery-3.6.1
