# to run the hmac example

gcc -o hmac_example hmac.c -lcrypto -lssl


# to run the pbc example

gcc -o pbc_example program.c -lpbc -lgmp
gcc -o new_example new_prg.c -lpbc -lgmp

# execute pbc example 

./pbc_example <param_a.txt

