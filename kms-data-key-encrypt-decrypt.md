AWS KMS Key Encrypt & Decrypt with Data Key

Using KMS `basic encryption` is easy, but it comes with a couple of drawbacks. 

1. Encrypting a significant amount of data is expensive as you have to 
    transmit all your data over the wire in order to encrypt it on Amazon’s server.
    
1. Transferring data over a network could cause potential security breaches and lead to an unauthorised disclosure of, or access to your data.

1. The built-in 4KB limitation prevents you from encrypting large files. You could chunk the data up and reassemble it later during decryption, but rather than doing that let us have a look how we can do better by applying envelope encryption.**

**Envelope Encryption** is a practice of encrypting plaintext data with a `Unique Data Key`, and then encrypting the `Data Ke`y with a key encryption key (KEK).

![Fig : AWS KMS Encryption & Decryption Data Key](https://raw.githubusercontent.com/miztiik/serverless-kms-key-rotator/master/images/01_aws_kms_envelope_encryption_data_key.png)

The above image shows the data encryption process in which the AWS KMS service produces a `Data Key` against with our previously created `Customer Master Key`, which is then used to encrypt our documents.

You can also follow this article in **[Youtube](https://www.youtube.com/watch?v=U5nDPagdLPk&t=0s&list=PLxzKY3wu0_FKok5gI1v4g4S-g-PLaW9YD&index=23)**

1. ### Create Customer Master Key(CMK)
    Lets create a new `Customer Master Key` that will be  used to encrypt data.
    ```sh
    aws kms create-key
    ```
    If no key policy is set, a special default policy is applied. This behaviour is different from creating a key in GUI.
    ```sh
    output
    {
        "KeyMetadata": {
            "AWSAccountId": "123411223344",
            "KeyId":"6fa6043b-2fd4-433b-83a5-3f4193d7d1a6",
            "Arn":"arn:aws:kms:us-east-1:123411223344:key/6fa6043b-2fd4-433b-83a5-3f4193d7d1a6",
            "CreationDate": 1547913852.892,
            "Enabled": true,
            "Description": "",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER"
        }
    }
    ```
    Note the `KeyId` from the above.

    #### Create an Key Alias
    ```sh
    aws kms create-alias \
        --alias-name "alias/kms-data-key-demo" \
        --target-key-id "cf84167d-44cb-4b07-b277-ae1ea21dbe4d"
    ```

1. ### Create a data key
    With our new `CMK` will now generate a `Data Key`. We will get a `CiphertextBlob` which is `base64` encoded and the blob contains meta-data about which `CMK` was used during data key creation. It will allow us to retrieve the plaintext key later on decryption. 
    ```sh
    # Generate the key and store it in a hidden directory called `.key`
    mkdir -p "./.key"
    aws kms generate-data-key \
        --key-id "alias/kms-data-key-demo" \
        --key-spec "AES_256" \
        --output text \
        --query CiphertextBlob | base64 --decode > "./.key/encrypted_data_key"
    ```
    **Note:** It is important to understand that AWS KMS does not keep any records of your `Data Key` on their servers ~ so you have to manage those keys by yourself.

    1. #### Extract `Plaintext Data Key` for encryption
        We need the plaintext version of our `CiphertextBlob` so that we can use it encrypt our data using our encryption tool `OpenSSL`.
    
    ```sh
    plaintext_data_key=$(aws kms decrypt \
                            --ciphertext-blob \
                            fileb://./.key/encrypted_data_key \
                            --output text \
                            --query Plaintext
                            )
    ```

1. ### Encrypt Data with CMK
        Lets begin the encryption of confidential data. You can use any tool for this, here, I will be using `OpenSSL`.
    ```sh  
    openssl enc -e -aes256 \
        -k "${plaintext_data_key}" \
        -in "test_file.txt" \
        -out "encrypted_data.txt"
    ```
    **Note:** _As we now have stored the decoded CyphertextBlob - `encrypted_data_key` and Plaintext Key - `plaintext_data_key` in our `.key/`directory, we can get rid of the `plaintext_data_key` after the data encryption is completed._

    ```sh
    # If you store the data in bash shell environment, you can `unset` the variable from memory.
    unset plaintext_data_key
    # If you ever store the plaintext in a file, you can use shred to remove it.
    # shred --iterations=100 --remove=wipesync --zero './.key/plaintext_data_key'
    ```

    1. #### Encrypted upload to S3
        If you wanted to upload files to S3 with the newly created key,
        ```sh
        aws s3 cp test_file.txt \
            s3://kms-key-rotation-test-bkt-01 \
            --sse aws:kms \
            --sse-kms-key-id "6fa6043b-2fd4-433b-83a5-3f4193d7d1a6"
        ```

1. ### Decrypt Data with CMK
    Since the encrypted data includes keyid, we dont have to mention the `key-id` when decrypting the data.

    ```sh
    aws kms decrypt --ciphertext-blob fileb://encrypted_test_file --output text --query Plaintext
    ```
    But the decrypted file is in base64 encoded. If we have to decode and save to file,
    ```sh
    aws kms decrypt --ciphertext-blob fileb://encrypted_test_file --output text --query Plaintext | base64 --decode > decrypted_test_file.txt
    ```

1. ### Rotate Customer Master Key( CMK )
    There are two ways of rotating your CMK,
    - Method 1 : Enable `Auto-Rotation` in KMS, rotates every `365` days
    - Method 2 : Manually rotate your CMK. You control the period

    #### Enable Automatic Key Rotation
    Get the current status of key rotation
    ```sh
    aws kms get-key-rotation-status --key-id 6fa6043b-2fd4-433b-83a5-3f4193d7d1a6
    ```
    If you get a output as below, `false`, that means it is not enabled. Lets enable it,
    ```sh
    aws kms enable-key-rotation --key-id 6fa6043b-2fd4-433b-83a5-3f4193d7d1a6
    ```
    Check the status again,
    ```sh
    aws kms get-key-rotation-status --key-id 6fa6043b-2fd4-433b-83a5-3f4193d7d1a6
    ```
    
    #### Manual Key Rotation
    Here you basically create a new CMK, [Create CMK](#create-cmk) and use the `alias` to point to the new CMK `KeyId`
    ![](https://docs.aws.amazon.com/kms/latest/developerguide/images/key-rotation-manual.png)
    
    ```sh
    # List current alias,
    aws kms list-aliases --key-id 6fa6043b-2fd4-433b-83a5-3f4193d7d1a6
    
    # If no alias, set one.
    aws kms create-alias --alias-name alias/my-shiny-encryption-key --target-key-id 6fa6043b-2fd4-433b-83a5-3f4193d7d1a6

    # Point the alias to new CMK KeyID
    aws kms update-alias --alias-name alias/my-shiny-encryption-key --target-key-id 0987dcba-09fe-87dc-65ba-ab0987654321
    ```
    **Note:** When you begin using the new CMK, be sure to keep the original CMK enabled so that AWS KMS can decrypt data that the original CMK encrypted. When decrypting data, KMS identifies the CMK that was used to encrypt the data, and it uses the same CMK to decrypt the data. As long as you keep both the original and new CMKs enabled, AWS KMS can decrypt any data that was encrypted by either CMK.

##### References
1. [Rotating Customer Master Keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html#rotate-keys-manually)