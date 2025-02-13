## Avail helios operator


To update a program make sure that correct program elf file is located in elf folder. 
To generate elf file follow the instructions on https://github.com/availproject/helios-sp1/blob/main/README.md 


To create init file run the following command:
```
cargo run --bin genesis
```
The genesis JSON file will be generated in the genesis folder.

To run the operator make sure you have the correct .env file described in .env.example file:
```
cargo run --bin operator
```
