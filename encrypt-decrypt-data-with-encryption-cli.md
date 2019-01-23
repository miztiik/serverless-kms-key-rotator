# Encrypt and Decrypt Your Data with AWS Encryption CLI

With the AWS Encryption CLI, you can take advantage of the advanced data protection built into the AWS Encryption SDK, including envelope encryption and strong algorithm suites.

The AWS Encryption CLI supports best-practice features, such as authenticated encryption with symmetric encryption keys and asymmetric signing keys, as well as unique data keys for each encryption operation. 

You can use the CLI with customer master keys (CMKs) from  KMS, master keys that you manage in AWS CloudHSM, or master keys from your own custom master key provider, but the AWS Encryption CLI does not require any AWS service.

![Fig : AWS KMS Encryption & Decryption](https://raw.githubusercontent.com/miztiik/serverless-kms-key-rotator/master/images/00_aws_kms_envelope_encryption_.png)

You can also follow this article in **[Youtube](https://www.youtube.com/watch?v=0VKJfpCoF2s&t=0s&index=37&list=PLxzKY3wu0_FIjhG_6Qyisxk1GccjHV2Fz)**

1. ### Install AWS Encryption CLI
    
    Use pip to install the AWS Encryption CLI and the Python cryptography library that it requires.
    ```sh
    pip install aws-encryption-sdk-cli

    # To find the version number of your AWS Encryption CLI and AWS Encryption SDK
    aws-encryption-cli --version
    ```

1. ### How to Encrypt and Decrypt Data
    Lets say you already have created a CMK and know its alias to be `alias/enc-key`. We will use this key to encrypt our data stored in a file called `confidential_data.txt`.


    ```sh
    # Set the `key_id` variable with the alias in memory
    key_id="alias/enc-key"

    # Encrypt the data and store the output under the directory `/encrypted_data`
    aws-encryption-cli --encrypt \
        --master-keys key="${key_id}" \
        --encryption-context "purpose=test" \
        --metadata-output "./metadata" \
        --input "confidential_data.txt" \
        --output "./encrypted_data/confidential_data.txt.encrypted"
    ```
    The `encryption-context` parameter (`-c`) is used to specify an encryption context, `purpose=test`, for the operation. The encryption context is _non-secret_ data that is cryptographically bound to the encrypted data and included in plaintext in the encrypted message that the CLI returns. Providing additional authenticated data, such as an encryption context, is a recommended best practice.

    The `--metadata-output` parameter tells the AWS Encryption CLI where to write the metadata for the encrypt command. The metadata includes the full paths to the input and output files, the encryption context, the algorithm suite, and other valuable information that you can use to review the operation and verify that it meets your security standards.


    **Note:** _As we now have stored the decoded CyphertextBlob - `encrypted_data_key` and Plaintext Key - `plaintext_data_key` in our `.key/`directory, we can get rid of the `plaintext_data_key` after the data encryption is completed._

    ```sh
    # If you store the data in bash shell environment, you can `unset` the variable from memory.
    unset plaintext_data_key
    # If you ever store the plaintext in a file, you can use shred to remove it.
    # shred --iterations=100 --remove=wipesync --zero './.key/plaintext_data_key'
    ```

1. ### Decrypting the data with `Data Key`
    Decrypting data is the most straightforward, assuming you have stored the `encrypted data key` securely and able to access it when required. In this demo, we have stored it under `.key` directory. We will need the plaintext copy of the data key.
    
    ```sh  
    aws-encryption-cli --decrypt \
        --encryption-context "purpose=test" \
        --metadata-output "./metadata" \
        --input "./encrypted_data/confidential_data.txt.encrypted" \
        --output "./decrypted_data/"
    ```

    The `--encryption-context` parameter supplies the same encryption context that was used in the encrypt command. This parameter is not required, but verifying the encryption context during decryption is a cryptographic best practice.

    The `--metatdata-output` parameter tells the command where to write the metadata for the decrypt command. If the file exists, this parameter appends the metadata to the existing file. The AWS Encryption CLI also has parameters that overwrite the metadata file or suppress the metadata.
