# Serverless KMS Key Rotator
This script helps you to rotate your CMK(Customer Master Key)

1. ## Create S3 Bucket

1. ## Create Custom Master Key(CMK) in KMS
    We will use this key exclusively for S3 usage

1. ## Upload Object to S3 - GUI
    Use the AES-256 Encryption while uploading

1. ## Upload Object to S3 - CLI with SSE header
    Set the upload header `x-amz-server-side​-encryption` and do not specify the key id, forcing S3 to use the default key

    _Ref: [Server-Side-Encryption-Specific Request Headers](https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html)_



1. ## Upload Object to S3 - CLI with AWS KMS - CMK ID


    ```
    PUT /example-object HTTP/1.1
    Host: example-bucket.s3.amazonaws.com   
    Accept: */*   
    Authorization:authorization string   
    Date: Wed, 28 May 2014 19:31:11 +0000   
    x-amz-server-side-encryption-customer-key:g0lCfA3Dv40jZz5SQJ1ZukLRFqtI5WorC/8SEEXAMPLE   
    x-amz-server-side-encryption-customer-key-MD5:ZjQrne1X/iTcskbY2example   
    x-amz-server-side-encryption-customer-algorithm:AES256
    ```

1. ## Disable & Delete CMK
    Download the objects encrypted 