#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
.. module: To Automatically rotate KMS Key perioidcally
    :platform: AWS
    :copyright: (c) 2019 Mystique.,
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Mystique
.. contactauthor:: miztiik@github issues
"""

from __future__ import print_function
import boto3
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
        global_vars['tag_name']                 = "serverless_kms_key_rotator"
        global_vars['kms_bucket']               = "kms-key-rotation-test-bkt-01"
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
        logger.error('ERROR: {0}'.format( str(e) ) )
        return False
    return True

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
    # Create the key, after checking for `key_policy` validity
    try:
        if is_json( key_policy ):
            resp = kms_client.create_key( Policy = key_policy)
                #Tags=[{'TagKey': 's3-key','TagValue': key_name},])
        else:
            resp = kms_client.create_key()
        # If alias_name is not set, use the `key_name` as the alias name, as it is good practices to use alias.
        if not alias_name:
            alias_name = key_name
        # Assign the alias to the key
        kms_client.create_alias( AliasName = f"alias/{alias_name}", TargetKeyId=response['KeyMetadata']['KeyId'] )
        resp['status'] = True
    except Exception as e:
        logger.error('ERROR: {0}'.format( str(e) ) )
        resp['error_message'] = str(e)
    return resp

def does_kms_key_exists(region_name, key_id ):
    """
    Check if the key exists for the given key_id

    :param region_name: The region where the key is to be created. KMS Keys are region specific
    :param type: str
    :param key_id: The CMK KeyId
    :param type: str

    :return: key_exists Returns True, If key exists, False If Not.
    :rtype: bool
    """
    kms_client = boto3.client('kms', region_name = region_name)
    key_exists = False
    try:
        cmks = kms_client.describe_key( KeyId = key_id )
        key_exists = True
    except NotFoundException as e:
        logger.error(f"Could not find a key matching KeyId:{key_id}, ERROR:{str(e)}")
    return key_exists

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
            text_data = '1234567890'
            logger.error(f"Invalid or No data provide for encryption. TextData: {text_data}")
        resp = kms_client.encrypt( KeyId = key_id, Plaintext = bytes(text_data) )
        resp['status'] = True
    except Exception as e:
        logger.error(f"Invalid or No encrypted data:{encrypted_blob}, ERROR:{str(e)}")
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
            logger.error(f"Invalid or No encrypted data:{encrypted_blob}")
            exit
        resp = kms_client.decrypt( CiphertextBlob = bytes(encrypted_blob) )
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
            logger.error(f"Invalid or No encrypted data:{encrypted_blob}")
            encrypted_blob = b'\x01\x02\x02...'
            # exit
        resp = kms_client.re_encrypt( CiphertextBlob= encrypted_blob, DestinationKeyId = dest_key_id )
        resp['status'] = True
    except Exception as e:
        logger.error(f"Invalid or No encrypted data:{encrypted_blob}, ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp
 
def encrypted_upload_to_s3(file_name, key_id, bucket_name):
    """
    Upload an Object to the given S3 `bucket_name` using the given KMS key_id`

    :param key_id: The CMK KeyId
    :param type: str

    :return: key_exists Returns True, If key exists, False If Not.
    :rtype: bool
    """
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4'))
    if not bucket_name: bucket_name = "kms-key-rotation-test-bkt-01"
    s3_client.upload_file(file_name, bucket_name, objectkey, ExtraArgs={"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": key_id })

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
    key_id = "6fa6043b-2fd4-433b-83e5-3f4193d7d1a6"
    kms_client.list_aliases( KeyId = key_id )
    # arn:aws:kms:us-east-1:589562693537:key/7fd98284-5c08-4b56-88e8-52d1305b6bb6

if __name__ == '__main__':
    lambda_handler(None, None)