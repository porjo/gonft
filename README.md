
## gonft

A high-level interface to Linux nftables, enabling basic manipulation of nftables from Go code

**NOTE:** this is currently proof-of-concept and not ready for real use


### Requirements

- libnftnl
- libmnl 
- linux kernel that includes the nf_tables subsystem (>= 3.14)

### Example usage

Have a look at [nft_example.go](https://github.com/porjo/gonft/blob/master/nft_example.go)

