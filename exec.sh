#!/bin/bash

openssl ecparam -noout -text -param_enc explicit -name secp256k1 | tee output.log