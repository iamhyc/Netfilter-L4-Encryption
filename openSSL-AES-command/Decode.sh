#! /bin/bash

openssl enc -aes-128-ecb -K $(cat key) -in $1 -out $2 -d
