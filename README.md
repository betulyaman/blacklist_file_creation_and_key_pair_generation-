Performs a one-time generation of all cryptographic key pairs required for secure file operations.
The generated keys are saved as standalone files so they can be deployed and consumed by the kernel-mode minifilter driver.

1. One-time key-pair generation
The application generates three independent key pairs:
- Kernel recipient key pair: Used by the minifilter to decrypt encrypted blacklist data.
- Sender encryption key pair (crypto_box): Used by the user-mode tool to encrypt data for the kernel recipient.
- Signing key pair (crypto_sign): Used to sign the serialized blacklist payload.
All keys are written to files (e.g., kernel_pub_key.txt, kernel_pri_key.txt, sender_pub_key.txt, sender_pri_key.txt, signer_pub_key.txt, signer_pri_key.txt).

2. Deploy required keys to the VM
Two key files must be copied manually to the VM so the minifilter driver can read them during initialization:
- kernel_pri_key.txt → C:\
- signer_pub_key.txt → C:\
These will be read by the driver after the file system becomes fully available.

3. Create and deploy an encrypted blacklist file
The tool builds an encrypted blacklist file using the following steps:
- Serialize the path list into a compact payload format.
- Sign the payload using the signing secret key.
- Construct a plaintext blob that includes: the signer public key, the signed message size, the signed message
- Encrypt the plaintext blob using crypto_box with a fresh random nonce.
- Build a header containing: nonce, sender encryption public key, ciphertext size
- Write header + ciphertext as the final encrypted blacklist file.
This encrypted output file (e.g., abc.txt) is then copied into the VM under: C:\FileSecDb\
The minifilter will read this encrypted file at boot-time (after the file system is fully mounted) and decrypt + verify its contents using the deployed keys.
