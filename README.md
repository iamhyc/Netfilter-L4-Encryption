For Windows platform network encryption, please refer to this cool stuff [tcpcrypt](http://tcpcrypt.org/).

> *NEED A WIRESHARK GIF PREVIEW HERE.*

## Introduction

This is a project trying to encrypt **Payload of L3** with *Symmetrical Encryption* based on *Linux Netfilter* subsystem.

Just imagine that the intermediate routers could not know what you are actually transmitting, on which protol with what content.

## Method

> *NEED UPDATE IN THE FUTURE*

## TODO

+ [x] ~~Asynchronous encyrption adding *waitting completion*~~
+ [x] ~~Encryption verified, *skb_put* verified~~
+ [x] ~~IPv4 checksum re-calculate~~
+ [x] ~~Decryption suite~~
+ [ ] Mod&Fix to suit 4.14+ kernel
+ [ ] use **genl** for dynamic AES_KEY from userspace
+ [ ] update encryption implementation
+ [ ] use **genl** for dynamic ALLOWED_ADDRESS_LIST from userspace
+ [ ] Exchange Allowed IP List with Customed **ICMP** Message
