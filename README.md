## Avail helios operator


To create init file run the following command:
```
cargo run --bin genesis
```
The genesis JSON file will be generated in the contracts folder.

To run the operator make sure you have the correct .env file described in .env.example file:
```
cargo run --bin operator
```
To generate elf from a program run:
```
cargo prove build --docker --tag v4.0.0-rc.3 --elf-name sp1-helios-elf 
```