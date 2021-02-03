import logging
from lib import calls as f

LOGGER = logging.getLogger(__name__)
KEY_FILE: str = '/tmp/pem'
# basic default secrets
secret_bitbucket_app_password = 'kdevops-api-key'
secrets_aws = {
    'pub_key': 'devops-pub',
    'pem_key': 'devops-pem'
}

bb_user = 'devops'
key_label = 'rotated-key'

f.aws_whois()

# Gets the api keys from AWS SECRET devops-bucket-devops-api-key (Logs do not output value)
api_key = str(f.get_secret(secret_bitbucket_app_password))
# print(api_key)
# LOGGER.debug('Bitbucket Password: %s', api_key)

auth = 'Basic ' + str(f.encode_auth(bb_user, api_key))
# print(auth)
# LOGGER.debug(auth)
uuid = f.get_bb_uuid(auth)
# print(uuid)

# Retrieve Bitbucket key uuid from /JENKINS:BOX/FILE_SYSTEM/file (To be determined by developer. not in the workspace.)
ssh_uuid = f.get_bb_users_key(key_label, uuid, auth)
# print(ssh_uuid)

# Delete existing key in bit bucket with uuid.
if ssh_uuid is not False:
    print(f.del_bb_users_ssh_key(ssh_uuid, uuid, auth))
else:
    print("No existing key to delete.")

# generates a new ssh key pair. (rsa)
new_key = f.generate_keypair(KEY_FILE)
# uses the Bitbucket api to upload the public key to the the Bitbucket user.
print(f.add_bb_users_ssh_key(key_label, uuid, auth, new_key['Public_key']))

# Tests access via ssh -i PEM.KEY.FILE git@bitbucket.org should return with a successful login.
connection = f.ssh_check('bitbucket.org', 'git', KEY_FILE)
# BREAK IF THIS FAILS AND ALERT VIA EMAIL
if connection is False:
    print("New Key failed to connect")
    exit(1)
else:
    print("New credentials worked adding to AWS.")

# Update AWS secret with private key value. devops-pem
new_pub_on_aws = f.aws_update_secret(secrets_aws['pub_key'], new_key['Public_key'])
new_pem_on_aws = f.aws_update_secret(secrets_aws['pem_key'], new_key['Private_key'])
# Deletes generated keypair from local system

