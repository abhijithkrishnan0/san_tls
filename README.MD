# SanTLS

## Prerequistes 

Included installation instruction for a macbook. These installation can be done on a linux system as well.

### Install OpenSSL

`brew install openssl`

### Install GMP and PBC

```
brew install gmp
brew install pbc
```


## Running the tests

Each directory has a `script.sh` which takes in an argument to start or kill the test. The number of middleboxes can be configured in each script. You can also update the script to give a custom input file which can be sent betweeen middleboxes and server.