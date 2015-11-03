'''
iOS9_iCloud_POC

Usage:
  iOS9_iCloud_POC.py [-d <device> -s <snapshot> -m <manifest>] (<token> | <appleid> <password>)
  iOS9_iCloud_POC.py --token <appleid> <password>
  iOS9_iCloud_POC.py (-h | --help)
  iOS9_iCloud_POC.py --version

Options:
  -d,--device <int>     Device, default: 0 = first device
  -s,--snapshot <int>   Snapshot, default: 0 = first snapshot
  -m,--manifest <int>   Manifest, default: 0 = first manifest
  --token               Display dsPrsID:mmeAuthToken token and exit
  -h --help             Show this screen
  --version             Show version
'''

########################################################################################################################
# Imports
########################################################################################################################

import sys
import os
import binascii
import base64
import requests
import logging
import httplib
import plistlib
from pprint import pprint
import json
from urlparse import urlparse
from cloud_kit_pb2 import RequestOperation, ResponseOperation, FileTokens
from chunk_server_pb2 import FileGroups
from pbuf import decode_protobuf_array, encode_protobuf_array
from docopt import docopt


########################################################################################################################
# Constants
########################################################################################################################

Client_Info = '<iPhone5,3> <iPhone OS;9.0.1;13A404> <com.apple.cloudkit.CloudKitDaemon/479 (com.apple.cloudd/479)>'
USER_AGENT_UBD = 'CloudKit/479 (13A404)'

########################################################################################################################
# Setup
########################################################################################################################

# Turn on debugging for requests module
httplib.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger('requests.packages.urllib3')
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


########################################################################################################################
# Common functions
########################################################################################################################

def debug(msg):
    print 'DEBUG: %s' % msg


def random_bytes(num_bytes):
    return binascii.b2a_hex(os.urandom(num_bytes))


def random_guid():
    return '%s-%s-%s-%s-%s' % (random_bytes(4), random_bytes(2), random_bytes(2), random_bytes(2), random_bytes(6))


def request(host, method, url, body, headers):
    uri = 'https://%s:%s' % (host, url)

    if method == 'GET':
        r = requests.get(uri, data=body, headers=headers)
    else:
        r = requests.post(uri, data=body, headers=headers)
    if r.status_code != 200:
        debug('_request: Request %s returned code %d' % (url, r.status_code))
        sys.exit(1)
    result_string = r.content
    #result_headers = r.headers
    return result_string


def plist_request(host, method, url, body, headers):
    '''
    Make a request and intrepret as a plist
    '''
    plist_string = request(host, method, url, body, headers)
    d = plistlib.readPlistFromString(plist_string)
    return d


def json_request(host, method, url, body, headers):
    '''
    Make a request and intrepret as json
    '''
    json_string = request(host, method, url, body, headers)
    d = json.loads(json_string)
    return d


def new_request_operation():
    '''
    Returns a requestOperation protobuf object with the requestOperationHeader filled out

    '''
    requestOperation = RequestOperation()
    roh = requestOperation.requestOperationHeader
    roh.applicationContainer = 'com.apple.backup.ios'
    roh.applicationBundle = 'com.apple.backupd'
    roh.deviceIdentifier.name = device_ID
    roh.deviceIdentifier.type = 2
    roh.deviceSoftwareVersion = '9.0.1'
    roh.deviceLibraryName = 'com.apple.cloudkit.CloudKitDaemon'
    roh.deviceLibraryVersion = '479'
    roh.operation = 'CKDFetchRecordZonesOperation'
    roh.deviceFlowControlBudget = 40000
    roh.deviceFlowControlBudgetCap = 40000
    roh.version = '4.0'
    roh.f19 = 1
    roh.deviceAssignedName = device_name
    roh.deviceHardwareID = device_ID
    roh.f23 = 1
    roh.f25 = 1

    return requestOperation


def retrieve_request(request_type):
    '''
    Returns a new request operation with the type specified
    '''
    requestOperation = new_request_operation()
    r = requestOperation.request
    r.uuid = random_guid()
    r.type = request_type
    r.f4 = 1
    return requestOperation


def find_records_with_identifier(protbuf_recordfield_list, identifier):
    '''
    Search through a list of recordFields and return the value with identifer.name == identifier
    '''
    for record_field in protbuf_recordfield_list:
        if record_field.identifier.name == identifier:
            return record_field.value
    # Not found
    return None


def main():
    # TODO can we retrieve these?
    global device_ID
    global device_name
    device_ID = random_bytes(32)
    device_name = 'My iPhone'

    # Parse arguments
    arguments = docopt(__doc__, version='iOS9_iCloud_POC 1.0')

    apple_id = arguments['<appleid>']
    apple_pw = arguments['<password>']
    if arguments['<token>']:
        dsPrsID, mmeAuthToken = arguments['<token>'].split(':')
        SKIP_AUTH = True
    else:
        SKIP_AUTH = False

    device_index = int(arguments['--device'] or 0)
    snapshot_index = int(arguments['--snapshot'] or 0)
    manifest_index = int(arguments['--manifest'] or 0)


    ####################################################################################################################
    # Step 1: Authenticaton
    ####################################################################################################################
    if not SKIP_AUTH:
        debug('Step 1: Authenticaton')

        auth = 'Basic %s' % base64.b64encode('%s:%s' % (apple_id, apple_pw))
        authenticateResponse = plist_request('setup.icloud.com', 'POST', '/setup/authenticate/$APPLE_ID$', '',
                                                             {'Authorization': auth,
                                                              'Connection': 'Keep-Alive'})
        if not authenticateResponse:
            debug('Invalid Apple ID/password?')
            sys.exit(1)
        pprint(authenticateResponse)

        dsPrsID = str(authenticateResponse['appleAccountInfo']['dsPrsID'])
        mmeAuthToken = authenticateResponse['tokens']['mmeAuthToken']
        if arguments['--token']:
            print '\nToken: %s:%s' % (dsPrsID, mmeAuthToken)
            sys.exit(1)

        # Cookies don't seem to be required
        #cookie = result_headers['set-cookie'].split(';')[0]

    else:
        debug('Skipping Step 1 (Authentication)')

    # noinspection PyUnboundLocalVariable
    auth = 'Basic %s' % base64.b64encode('%s:%s' % (dsPrsID, mmeAuthToken))


    ####################################################################################################################
    # STEP 2. Account settings.
    ####################################################################################################################
    debug('\nSTEP 2. Account settings.')
    if not SKIP_AUTH:
        account_settings = plist_request('setup.icloud.com', 'POST', '/setup/get_account_settings', '',
                                                            {'Authorization': auth,
                                                             'X-MMe-Client-Info': Client_Info,
                                                             'User-Agent': USER_AGENT_UBD
                                                             # 'Cookie': cookie
                                                             })
    else:
        account_settings = plist_request('setup.icloud.com', 'POST', '/setup/get_account_settings', '',
                                                            {'Authorization': auth,
                                                             'X-MMe-Client-Info': Client_Info,
                                                             'User-Agent': USER_AGENT_UBD})

    pprint(account_settings)
    cloud_kit_token = account_settings['tokens']['cloudKitToken']
    # if SKIP_AUTH:
    #     cookie = result_headers['set-cookie'].split(';')[0]


    ####################################################################################################################
    # STEP 3. CloudKit Application Initialization.
    ####################################################################################################################
    debug('\nSTEP 3. CloudKit Application Initialization.')
    # Note, we aren't passing all the headers that Inflatable does or even that the real iphone does
    # But our response seem to be the same
    cloudkit_init = json_request('setup.icloud.com', 'POST', '/setup/ck/v1/ckAppInit?container=com.apple.backup.ios', '',
                                    {'Authorization': auth,
                                     'X-MMe-Client-Info': Client_Info,
                                     'X-CloudKit-AuthToken': cloud_kit_token,
                                     'X-CloudKit-ContainerId': 'com.apple.backup.ios',
                                     'X-CloudKit-BundleId': 'com.apple.backupd',
                                     'X-CloudKit-Environment': 'production',
                                     'X-CloudKit-Partition': 'production',
                                     'User-Agent': USER_AGENT_UBD
                                     # 'Cookie': cookie
                                     })

    pprint(cloudkit_init)

    ckdatabase_host = urlparse(cloudkit_init['cloudKitDatabaseUrl']).hostname
    cloudkit_user_id = cloudkit_init['cloudKitUserId']


    ####################################################################################################################
    # STEP 4. Record zones.
    #Returns record zone data which needs further analysis.
    ####################################################################################################################
    debug('\nSTEP 4. Record zones.')

    requestOperation = retrieve_request(201)
    # zoneRetrieveRequest
    zrr = requestOperation.zoneRetrieveRequest
    zrr.zoneIdentifier.value.name = 'mbksync'
    zrr.zoneIdentifier.value.type = 6
    zrr.zoneIdentifier.ownerIdentifier.name = cloudkit_user_id
    zrr.zoneIdentifier.ownerIdentifier.type = 7

    debug(requestOperation)
    body = encode_protobuf_array([requestOperation])
    cloudkit_header = {'X-MMe-Client-Info': Client_Info,
                       'X-Apple-Request-UUID': random_guid(),
                       'X-CloudKit-UserId': cloudkit_user_id,
                       'X-CloudKit-AuthToken': cloud_kit_token,
                       'X-CloudKit-ContainerId': 'com.apple.backup.ios',
                       'X-CloudKit-BundleId': 'com.apple.backupd',
                       'X-CloudKit-ProtocolVersion': 'client=1;comments=1;device=1;presence=1;records=1;sharing=1;subscriptions=1;users=1;mescal=1;',
                       'Accept': 'application/x-protobuf',
                       'Content-Type': 'application/x-protobuf; desc="https://p33-ckdatabase.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; messageType=RequestOperation; delimited=true',
                       'User-Agent': USER_AGENT_UBD
                       # 'Cookie': cookie
                       }

    pbuf_string = request(ckdatabase_host, 'POST', '/api/client/record/retrieve', body, cloudkit_header)
    zone_retrieve_response = decode_protobuf_array(pbuf_string, ResponseOperation)[0]
    debug(zone_retrieve_response)


    ####################################################################################################################
    #STEP 5. Backup list
    #Returns device data/ backups.
    ####################################################################################################################
    debug('\nSTEP 5. Backup list.')

    requestOperation = retrieve_request(211)
    # recordRetrieveRequest
    rrr = requestOperation.recordRetrieveRequest
    rrr.recordID.value.name = 'BackupAccount'
    rrr.recordID.value.type = 1
    rrr.recordID.zoneIdentifier.value.name = 'mbksync'
    rrr.recordID.zoneIdentifier.value.type = 6
    rrr.recordID.zoneIdentifier.ownerIdentifier.name = cloudkit_user_id
    rrr.recordID.zoneIdentifier.ownerIdentifier.type = 7
    rrr.f6.value = 1

    debug(requestOperation)
    body = encode_protobuf_array([requestOperation])
    cloudkit_header['X-Apple-Request-UUID'] = random_guid()
    pbuf_string = request(ckdatabase_host, 'POST', '/api/client/record/retrieve', body, cloudkit_header)
    record_retrieve_response = decode_protobuf_array(pbuf_string, ResponseOperation)[0]
    debug(record_retrieve_response)

    # What is this thing? Is it really an id associated with a particular backup?
    devices = find_records_with_identifier(
        record_retrieve_response.recordRetrieveResponse.record.recordField,
        'devices'
    )
    if device_index >= len(devices.recordFieldValue):
        print 'No such device. Available devices: %s' % devices
        sys.exit(1)

    backup_id = devices.recordFieldValue[device_index].referenceValue.recordIdentifier.value.name


    ####################################################################################################################
    #STEP 6. Snapshot list (+ Keybag)
    # Message type 211 with the required backup uuid, protobuf array encoded.
    #          Returns device/ snapshots/ keybag information.
    #          Timestamps are hex encoded double offsets to 01 Jan 2001 00:00:00 GMT (Cocoa/ Webkit reference date).
    ####################################################################################################################
    debug('\nSTEP 6. Snapshot list (+ Keybag)')

    requestOperation = retrieve_request(211)
    # recordRetrieveRequest
    rrr = requestOperation.recordRetrieveRequest
    rrr.recordID.value.name = backup_id
    rrr.recordID.value.type = 1
    rrr.recordID.zoneIdentifier.value.name = 'mbksync'
    rrr.recordID.zoneIdentifier.value.type = 6
    rrr.recordID.zoneIdentifier.ownerIdentifier.name = cloudkit_user_id
    rrr.recordID.zoneIdentifier.ownerIdentifier.type = 7
    rrr.f6.value = 1

    debug(requestOperation)
    body = encode_protobuf_array([requestOperation])
    cloudkit_header['X-Apple-Request-UUID'] = random_guid()
    pbuf_string = request(ckdatabase_host, 'POST', '/api/client/record/retrieve', body, cloudkit_header)
    record_retrieve_response = decode_protobuf_array(pbuf_string, ResponseOperation)[0]
    debug(record_retrieve_response)

    snapshots = find_records_with_identifier(
        record_retrieve_response.recordRetrieveResponse.record.recordField,
        'snapshots'
    )

    if snapshot_index >= len(snapshots.recordFieldValue):
        print 'No such snapshot. Available snapshots: %s' % snapshots
        sys.exit(0)

    a_snapshot = snapshots.recordFieldValue[snapshot_index].referenceValue.recordIdentifier.value.name

    current_keybag_UUID = find_records_with_identifier(
        record_retrieve_response.recordRetrieveResponse.record.recordField,
        'currentKeybagUUID'
    ).stringValue


    ####################################################################################################################
    # STEP 7. Manifest list.
    #
    #          Url/ headers as step 6.
    #          Message type 211 with the required snapshot uuid, protobuf array encoded.
    #          Returns system/ backup properties (bytes ? format ?? proto), quota information and manifest details.
    ####################################################################################################################
    debug('\nSTEP 7. Manifest list')

    requestOperation = retrieve_request(211)
    # recordRetrieveRequest
    rrr = requestOperation.recordRetrieveRequest
    rrr.recordID.value.name = a_snapshot
    rrr.recordID.value.type = 1
    rrr.recordID.zoneIdentifier.value.name = 'mbksync'
    rrr.recordID.zoneIdentifier.value.type = 6
    rrr.recordID.zoneIdentifier.ownerIdentifier.name = cloudkit_user_id
    rrr.recordID.zoneIdentifier.ownerIdentifier.type = 7
    rrr.f6.value = 1

    debug(requestOperation)
    body = encode_protobuf_array([requestOperation])
    cloudkit_header['X-Apple-Request-UUID'] = random_guid()
    pbuf_string = request(ckdatabase_host, 'POST', '/api/client/record/retrieve', body, cloudkit_header)
    record_retrieve_response = decode_protobuf_array(pbuf_string, ResponseOperation)[0]
    debug(record_retrieve_response)

    manifest_ids = find_records_with_identifier(
        record_retrieve_response.recordRetrieveResponse.record.recordField,
        'manifestIDs'
    )
    if manifest_index >= len(manifest_ids.recordFieldValue):
        print 'No such manifest. Available manifests: %s' % manifest_ids
    a_manifest_id = manifest_ids.recordFieldValue[manifest_index].stringValue


    ########################################################################################################################
    # STEP 8. Retrieve list of files.
    #
    #          Url/ headers as step 7.
    #          Message type 211 with the required manifest, protobuf array encoded.
    #          Returns system/ backup properties (bytes ? format ?? proto), quota information and manifest details.
    #
    #          Returns a rather somewhat familiar looking set of results but with encoded bytes.
    ########################################################################################################################
    debug('\nSTEP 8. Retrieve list of files.')

    requestOperation = retrieve_request(211)
    # recordRetrieveRequest
    rrr = requestOperation.recordRetrieveRequest
    rrr.recordID.value.name = a_manifest_id + ':0'
    rrr.recordID.value.type = 1
    rrr.recordID.zoneIdentifier.value.name = '_defaultZone'
    rrr.recordID.zoneIdentifier.value.type = 6
    rrr.recordID.zoneIdentifier.ownerIdentifier.name = cloudkit_user_id
    rrr.recordID.zoneIdentifier.ownerIdentifier.type = 7
    rrr.f6.value = 1

    debug(requestOperation)
    body = encode_protobuf_array([requestOperation])
    cloudkit_header['X-Apple-Request-UUID'] = random_guid()
    pbuf_string = request(ckdatabase_host, 'POST', '/api/client/record/retrieve', body, cloudkit_header)
    record_retrieve_response = decode_protobuf_array(pbuf_string, ResponseOperation)[0]
    debug(record_retrieve_response)

    asset_tokens = find_records_with_identifier(
        record_retrieve_response.recordRetrieveResponse.record.recordField,
        'files'
    )

    if asset_tokens is None:
        print 'No files found'
        sys.exit(0)

    # Right now just grabbing the first file.
    # InflatableDonkey looks for the first file that is non 0 length
    # an_asset_token = asset_tokens.recordFieldValue[0].referenceValue.recordIdentifier.value.name
    length = 0
    an_asset_token = None
    for record_field_value in asset_tokens.recordFieldValue:
        an_asset_token = record_field_value.referenceValue.recordIdentifier.value.name
        # F:UUID:token:length:x
        _, uuid, token, length, x = an_asset_token.split(':')
        if int(length) > 0: break
    if int(length) == 0:
        print 'All files are 0 length'
        sys.exit(0)


    ########################################################################################################################
    # STEP 9. Retrieve asset tokens.
    #
    #          Url/ headers as step 8.
    #          Message type 211 with the required file, protobuf array encoded.
    ########################################################################################################################
    debug('\nSTEP 9. Retrieve asset tokens.')

    requestOperation = retrieve_request(211)
    # recordRetrieveRequest
    rrr = requestOperation.recordRetrieveRequest
    rrr.recordID.value.name = an_asset_token
    rrr.recordID.value.type = 1
    rrr.recordID.zoneIdentifier.value.name = '_defaultZone'
    rrr.recordID.zoneIdentifier.value.type = 6
    rrr.recordID.zoneIdentifier.ownerIdentifier.name = cloudkit_user_id
    rrr.recordID.zoneIdentifier.ownerIdentifier.type = 7
    rrr.f6.value = 1

    debug(requestOperation)
    body = encode_protobuf_array([requestOperation])
    cloudkit_header['X-Apple-Request-UUID'] = random_guid()
    pbuf_string = request(ckdatabase_host, 'POST', '/api/client/record/retrieve', body, cloudkit_header)
    record_retrieve_response = decode_protobuf_array(pbuf_string, ResponseOperation)[0]
    debug(record_retrieve_response)

    value = find_records_with_identifier(
        record_retrieve_response.recordRetrieveResponse.record.recordField,
        'contents'
    )
    # I think these are file attributes
    try:
        asset_value = value.assetValue
    except AttributeError:
        print 'No asset token found.'
        sys.exit(0)


    ####################################################################################################################
    # STEP 10. AuthorizeGet.
    #
    #          Process somewhat different to iOS8.
    #
    #          New headers/ mmcs auth token. See AuthorizeGetRequestFactory for details.
    #          Returns a ChunkServer.FileGroup protobuf which is largely identical to iOS8
    ####################################################################################################################
    debug('\nSTEP 10. AuthorizeGet.')

    mmcsAuthToken = '%s %s %s' % (
        asset_value.fileChecksum.encode('hex'),
        asset_value.fileSignature.encode('hex'),
        asset_value.downloadToken
    )

    headers = {
        'Accept': 'application/vnd.com.apple.me.ubchunk+protobuf',
        'Content-Type': 'application/vnd.com.apple.me.ubchunk+protobuf',
        'x-apple-mmcs-dataclass': 'com.apple.Dataclass.CloudKit',
        'X-CloudKit-Container': 'com.apple.backup.ios',
        'X-CloudKit-Zone': '_defaultZone',
        'x-apple-mmcs-auth': mmcsAuthToken,
        'x-apple-mme-dsid': dsPrsID,
        'User-Agent': USER_AGENT_UBD,
        'x-apple-mmcs-proto-version': '4.0',
        'X-Mme-Client-Info': '<iPhone5,3> <iPhone OS;9.0.1;13A404> <com.apple.cloudkit.CloudKitDaemon/479 (com.apple.cloudd/479)>'
    }

    # The body is a protobuf object FileTokens
    file_tokens = FileTokens()
    file_token = file_tokens.fileTokens.add()
    file_token.fileChecksum = asset_value.fileChecksum
    file_token.token = asset_value.downloadToken
    file_token.fileSignature = asset_value.fileSignature

    body = file_tokens.SerializeToString()
    host = urlparse(asset_value.contentBaseURL).hostname
    url = '/' + dsPrsID + '/authorizeGet'
    pbuf_string = request(host, 'POST', url, body, headers)

    file_groups = FileGroups()
    file_groups.ParseFromString(pbuf_string)

    debug(file_groups)


    ####################################################################################################################
    # STEP 11. ChunkServer.FileGroups.
    #
    # TODO.
    ####################################################################################################################


    ####################################################################################################################
    # STEP 12. Assemble assets/ files.
    ####################################################################################################################
    debug('\nSTEP 12. Assemble assets/files.')

    requestOperation = retrieve_request(220)
    # recordRetrieveRequest
    qrr = requestOperation.queryRetrieveRequest
    record_type = qrr.query.type.add()
    record_type.name = 'PrivilegedBatchRecordFetch'
    query_filter = qrr.query.filter.add()
    query_filter.fieldName.name = '___recordID'
    query_filter.fieldValue.type = 5
    query_filter.fieldValue.referenceValue.recordIdentifier.value.name = 'K:' + current_keybag_UUID
    query_filter.fieldValue.referenceValue.recordIdentifier.value.type = 1
    query_filter.fieldValue.referenceValue.recordIdentifier.zoneIdentifier.value.name = 'mbksync'
    query_filter.fieldValue.referenceValue.recordIdentifier.zoneIdentifier.value.type = 6
    query_filter.fieldValue.referenceValue.recordIdentifier.zoneIdentifier.ownerIdentifier.name = cloudkit_user_id
    query_filter.fieldValue.referenceValue.recordIdentifier.zoneIdentifier.ownerIdentifier.type = 7
    query_filter.type = 1

    qrr.zoneIdentifier.value.name = 'mbksync'
    qrr.zoneIdentifier.value.type = 6
    qrr.zoneIdentifier.ownerIdentifier.name = cloudkit_user_id
    qrr.zoneIdentifier.ownerIdentifier.type = 7
    qrr.f6.value = 1

    debug(requestOperation)
    body = encode_protobuf_array([requestOperation])
    cloudkit_header['X-Apple-Request-UUID'] = random_guid()
    pbuf_string = request(ckdatabase_host, 'POST', '/api/client/query/retrieve', body, cloudkit_header)
    record_retrieve_response = decode_protobuf_array(pbuf_string, ResponseOperation)[0]
    debug(record_retrieve_response)

    debug('Done')


if __name__ == '__main__':
    main()
