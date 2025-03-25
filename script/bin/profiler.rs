use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};


const HELIOS_ELF: &[u8] = include_bytes!("../../elf/sp1-helios-elf");
const INPUT_STREAM: u32 = 1000;


fn main() {
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();
    stdin.write(&INPUT_STREAM);

    let client = ProverClient::from_env();

    let (_, sp1_report) = client.execute(HELIOS_ELF, &stdin).run().unwrap();

    println!("executed program with {} cycles", sp1_report.total_instruction_count());

    let (pk, vk) = client.setup(HELIOS_ELF);

    let mut proof = client.prove(&pk, &stdin).compressed().run().unwrap();

    println!("generated proof");

    let _ = proof.public_values.read::<u32>();
    let proof_outputs = proof.public_values.read::<u32>();

    println!("This is the SP1 Helios program proof output: {}", proof_outputs);

    client.verify(&proof, &vk).expect("verification failed");

    proof.save("failed-proof.bin").expect("saving proof failed");

    let deserialized_proof = SP1ProofWithPublicValues::load("failed-proof.bin").expect("loading proof failed");

    client.verify(&deserialized_proof, &vk).expect("verification failed");

}
