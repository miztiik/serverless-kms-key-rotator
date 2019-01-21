AWS KMS Key Encrypt | Decrypt | Key Rotation
AWS KMS encrypts your data with encryption keys that you manage. It is also integrated with AWS CloudTrail to provide encryption key usage logs to help meet your auditing, regulatory and compliance needs.

![Fig : AWS KMS Encryption & Decryption](https://raw.githubusercontent.com/miztiik/serverless-kms-key-rotator/master/images/00_aws_kms_envelope_encryption_.png)

You can also follow this article in **[Youtube](https://www.youtube.com/watch?v=U5nDPagdLPk&t=0s&list=PLxzKY3wu0_FKok5gI1v4g4S-g-PLaW9YD&index=23)**

1. ### Create CMK
    Lets create a new Customer Master Key that will be  used to encrypt data.
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
    An _alias_ is an optional display name for a CMK. To simplify code that runs in multiple regions, you can use the same alias name but point it to a different CMK in each region.
    ```sh
    aws kms create-alias \
        --alias-name "alias/kms-demo" \
        --target-key-id "6fa6043b-2fd4-433b-83a5-3f4193d7d1a6"
    ```

1. ### Encrypt Data with CMK
    Lets encrypt a local file `test_file.txt`
    ```sh
    aws kms encrypt --key-id 6fa6043b-2fd4-433b-83a5-3f4193d7d1a6 --plaintext fileb://test_file.txt --output text --query CiphertextBlob

    # If you want the base64 encoded data to be saved to a file
    aws kms encrypt --key-id 6fa6043b-2fd4-433b-83a5-3f4193d7d1a6 --plaintext fileb://test_file.txt --output text --query CiphertextBlob | base64 --decode > encrypted_test_file
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