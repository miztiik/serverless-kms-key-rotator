#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
.. module: To create encrypt/decrypt data with KMS CMKs
    :platform: AWS
    :copyright: (c) 2019 Mystique.,
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Mystique
.. contactauthor:: miztiik@github issues
"""

from __future__ import print_function
import boto3
import os
import base64
import json
import logging
from botocore.client import Config
from botocore.client import ClientError

# Initialize Logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def set_global_vars():
    """
    Set the Global Variables
    If User provides different values, override defaults

    This function returns the AWS account number

    :return: global_vars
    :rtype: dict
    """
    global_vars = {'status': False}
    try:
        global_vars['Owner']                    = "Mystique"
        global_vars['Environment']              = "Prod"
        global_vars['aws_region']               = "us-east-1"
        global_vars['tag_name']                 = "kms_helper"
        global_vars['key_rotation_frequency']   = 180
        global_vars['status']                   = True
    except Exception as e:
        logger.error("Unable to set Global Environment variables. Exiting")
        global_vars['error_message']            = str(e)
    return global_vars

def is_json(src_json):
    """
    Validate JSON file

    :param src_json: Source JSON to be checked
    :param type: str

    :return boolean: Return True if it is a valid JSON file, else return False
    :rtype: json
    """
    try:
        json_object = json.loads(src_json)
    except Exception as e:
        return False
    return True

def does_kms_key_exists(region_name, key_id):
    """
    Check if the key exists for the given key_id

    :param region_name: The region where the key is to be created. KMS Keys are region specific
    :param type: str
    :param key_id: The CMK KeyId or Alias or ARN
    :param type: str

    :return: key_exists Returns True, If key exists, False If Not.
    :rtype: bool
    """
    kms_client = boto3.client('kms', region_name = region_name)
    key_exists = False
    try:
        cmks = kms_client.describe_key( KeyId = str(key_id) )
        key_exists = True
    except ClientError as e:
        key_exists = False
        # logger.error(f"Key matching KeyId:{key_id} not found, ERROR:{str(e)}")
    return key_exists

def create_key_alias(region_name, alias_name, key_id):
    """
    Check if the key exists for the given key_id

    :param region_name: The region where the key is to be created. KMS Keys are region specific
    :param type: str
    :param alias_name: The CMK Alias
    :param type: str
    :param key_id: The CMK KeyId or Alias or ARN
    :param type: str

    :return: alias_created - Returns True, If alias created, False If Not.
    :rtype: bool
    """
    kms_client = boto3.client('kms', region_name = region_name)
    alias_created = False
    if alias_name:
        try:
            response = kms_client.create_alias( AliasName = f"alias/{alias_name}", TargetKeyId = key_id )
            alias_created = True
        except ClientError as e:
            logger.error(f"Could not add Alias:{alias_name} to Key:{key_id}, ERROR:{str(e)}")
    return alias_created

def update_key_alias(region_name, alias_name, target_key_id):
    """
    Update the target of the key alias

    :param region_name: The region where the key is to be created. KMS Keys are region specific
    :param type: str
    :param alias_name: The CMK Alias
    :param type: str
    :param target_key_id: The target CMK KeyId or Alias or ARN
    :param type: str

    :return: alias_created - Returns True, If alias created, False If Not.
    :rtype: bool
    """
    kms_client = boto3.client('kms', region_name = region_name)
    alias_created = False
    if alias_name:
        try:
            # Key alias MUST exist before it is re-assigned
            if does_kms_key_exists(region_name, f"alias/{alias_name}"):
                response = kms_client.update_alias( AliasName = f"alias/{alias_name}", TargetKeyId = target_key_id )
                alias_created = True
        except ClientError as e:
            logger.error(f"Could not add Alias:{alias_name} to Key:{key_id}, ERROR:{str(e)}")
    return alias_created

def create_kms_key(region_name, key_name, key_policy, alias_name = None):
    """
    Create a KMS key and a alias based on the given policy

    :param key_name: Name of the KMS Key
    :param type: str
    :param region_name: The region where the key is to be created. KMS Keys are region specific
    :param type: str
    :param key_policy: The key policy, on who can access or modify the key. Valid JSON expected.
    :param type: str
    :param key_alias: Name of the alias to be associated with the key
    :param type: str

    :return resp: Return json with status of key creation
    :rtype: json
    """
    kms_client = boto3.client('kms', region_name = region_name)
    resp = { 'status':False, 'error_message':'', 'objs':[] }
    try:
        # Create the key, after checking for `key_policy` validity
        if is_json( key_policy ):
            resp = kms_client.create_key( Policy = key_policy)
        else:
            logger.info(f"WARNING: No valid Key Policy was provided, Using default policy.")
            resp = kms_client.create_key()
        # Create alias only if requested
        if alias_name:
            # Key Alias MUST be unique per region, Lets check first if key alias exists.
            if not does_kms_key_exists(region_name, alias_name):
                logger.info(f"INFO: Proceeding to create new KMS Alias")
                alias_status = create_key_alias(region_name, alias_name, resp.get('KeyMetadata').get('KeyId') )
                if not alias_status:
                    resp['error_message'] = "Unable to create Alias"
        resp['status'] = True
    except Exception as e:
        logger.error('ERROR: {0}'.format( str(e) ) )
        resp['error_message'] = str(e)
    return resp

def encrypt_text(region_name, key_id, text_data = None):
    """
    Encrypt plain `text_data` using the `key_id`

    :param region_name: The region where the key is to be created. KMS Keys are region specific
    :param type: str
    :param key_id: The CMK KeyId
    :param type: str
    :param text_data: The data to be encrypted
    :param type: str

    :return: resp The encrypted blob text in base64 encoding along with the HTTPStatusCode and content-length
    :rtype: json
    """
    kms_client = boto3.client('kms', region_name = region_name)
    resp = {'status': False}
    try:
        if not text_data:
            text_data = "This is Great Stuff"
            logger.error(f"Invalid or No data provide for encryption. TextData: {text_data}")
        resp = kms_client.encrypt( KeyId = key_id, Plaintext = text_data )
        resp['status'] = True
    except Exception as e:
        logger.error(f"Invalid or Not Plain text:{text_data}, ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp

def decrypt_blob(region_name, key_id, encrypted_blob):
    """
    Encrypt plain `text_data` using the `key_id`

    :param region_name: The region where the key is to be created. KMS Keys are region specific
    :param type: str
    :param key_id: The CMK KeyId
    :param type: str
    :param encrypted_blob: The encrypted base64 encoded data
    :param type: base64 encoded str

    :return: resp The encrypted blob text in base64 encoding along with the HTTPStatusCode and content-length
    :rtype: json
    """
    kms_client = boto3.client('kms', region_name = region_name)
    resp = {'status': False}
    try:
        if not encrypted_blob:
            logger.info(f"INFO:Invalid or No encrypted data:{encrypted_blob}")
            exit
        resp = kms_client.decrypt( CiphertextBlob = encrypted_blob )
        #resp = kms_client.decrypt( CiphertextBlob = bytes(base64.b64decode(encrypted_blob)) )
        resp['status'] = True
    except Exception as e:
        logger.error(f"Invalid or No encrypted data:{encrypted_blob}, ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp

def re_encrypt_with_new_key(region_name, dest_key_id, encrypted_blob):
    """
    Change/Rotate the encryption key of the object. The data is first decrypted and then encrypted using the `new_key_id`

    :param region_name: The region where the key is to be created. KMS Keys are region specific
    :param type: str
    :param dest_key_id: The new CMK KeyID
    :param type: str
    :param encrypted_blob: The encrypted base64 encoded data
    :param type: base64 encoded str

    :return: resp The encrypted blob text in base64 encoding along with the HTTPStatusCode and content-length
    :rtype: json
    """
    kms_client = boto3.client('kms', region_name = region_name)
    resp = {'status': False}
    try:
        if not encrypted_blob:
            logger.info(f"INFO:Invalid or No encrypted data:{encrypted_blob}")
            encrypted_blob = b'\x01\x02\x02\x00xh\xb9\xf2\xef\xe0\xa2\xa3\xe8\x97w\xb7\xb7\x95\xe6{\xdfFU\xf9\xbc\xdd\x8cupd\xc5H\x88\xb8\xce\x824\x01\xac\xf0\xac\xc6\xc5P\x81\x17\n2\xb2\xb9\xd9\xbd7\xcb\x00\x00\x00q0o\x06\t*\x86H\x86\xf7\r\x01\x07\x06\xa0b0`\x02\x01\x000[\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04\x01.0\x11\x04\x0c\xa5\xe6\x91\xf4\xb2Y\xca$\xfc`\x99\xad\x02\x01\x10\x80. \xe2\x86\xea\x0c\xcb\xc6.s\x0c\xac\xa8\xd0\x04\x11\xec2\x00\x13\xaa\xb2+\x99\xfc\xcf\xbcp\xa2\xb9\x80\x0e\xb8\xca\x14>k\xd4C4L\xa0m{m\xf4\t'
            # exit
        resp = kms_client.re_encrypt( CiphertextBlob= encrypted_blob, DestinationKeyId = dest_key_id )
        resp['status'] = True
    except Exception as e:
        logger.error(f"Invalid or No encrypted data:{encrypted_blob}, ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp

def read_from_file(file_name):
    """
    Read the given file from local filesystem

    :param file_name: The name of the file to be read
    :param type: str

    :return: file_data The contents of the file.
    :rtype: str
    """
    file_data = None
    print(file_name)
    try:
        with open(file_name, 'r') as f:
            file_data = f.read()
    except Exception as e:
        logger.error(f"Unable to read/Open File: {file_name}, ERROR:{str(e)}")
    return file_data

def encrypted_upload_to_s3(file_name, key_id, bucket_name):
    """
    Upload an Object to the given S3 `bucket_name` using the given KMS key_id`

    :param file_name: The file to be uploaded
    :param type: str
    :param key_id: The CMK KeyId
    :param type: str
    :param bucket_name: The name of the S3 bucket
    :param type: str

    :return: obj_upload Returns True/False, aalong with error message.
    :rtype: json
    """
    obj_upload = {'status': False}
    s3 = boto3.resource('s3', config=Config(signature_version='s3v4'))
    try:
        if file_name and bucket_name and key_id:
            key_name = os.path.basename(file_name)
            file_data = read_from_file(file_name)
            if file_data:
                obj_upload['response'] = s3.meta.client.upload_file( Filename=file_name, Bucket=bucket_name, Key=key_name, ExtraArgs={"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": key_id } )
                obj_upload['status'] = True
            else:
                obj_upload['error_message'] = "Unable to get file contents"
        else:
            obj_upload['error_message'] = "Ensure all the parameter(s) are set"
    except Exception as e:
        logger.error(f"Unable to upload object: {file_name} to Bucket: {bucket_name}, ERROR:{str(e)}")
        obj_upload['error_message'] = str(e)
    return obj_upload

def lambda_handler(event, context):
    """
    Entry point for all processing. Load the global_vars

    :return: A dictionary of tagging status
    :rtype: json
    """
    """
    Can Override the global variables using Lambda Environment Parameters
    """
    global_vars = set_global_vars()

    if not global_vars.get('status'):
        logger.error('ERROR: {0}'.format( global_vars.get('error_message') ) )
        exit

    kms_client = boto3.client('kms')
    # Get list of customer master keys (CMKs)
    cmks = kms_client.list_keys()

    return cmks

if __name__ == '__main__':
    lambda_handler(None, None)