"""
  Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end
"""
import json
import threading
import requests
import datetime
from requests import post
from collections import defaultdict
from .constants import *
from integrations.crudhub import make_request
from connectors.core.connector import get_logger, ConnectorError
from django.conf import settings

logger = get_logger('crowdstrike-falcon')


class Falcon_RTR(object):
    def __init__(self, config):
        """
        Initialize a Falcon API instance.
        :param host: The URL for the CrowdStrike Falcon server.
        :param api_key: The API key generated on the CrowdStrike Falcon  API Key page.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        """
        self.base_url = config.get("server_url")
        if self.base_url[:8] == "https://":
            self.base_url = "{0}".format(self.base_url)
        else:
            self.base_url = "https://{0}".format(self.base_url)

        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.verify_ssl = config.get("verify_ssl")
        self.access_token = None
        self.response = None
        self.session_id = None
        self.device_id = None
        self.batch_id = None
        self.cloud_request_id = None
        self.cmds_available = []
        self.cmds_help = {}
        self.queue_offline = False
        self.headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json',
        }
        self.timer = None
        self.generate_token()

    def __del__(self):
        self.session_delete()

    def api_request(self, path, verb=None, params=None, file_dict=None, data=None, json_data=None, hunt=None):
        url = "{0}{1}".format(self.base_url, path)
        logger.debug('[{0}] URL: {1}'.format(verb, url))
        try:
            self.response = requests.request(
                url=url,
                method=verb,
                headers=self.headers,
                params=params,
                files=file_dict,
                data=data,
                json=json_data,
                verify=self.verify_ssl
            )
            logger.debug('HTTP: {0} | {1}'.format(self.response.status_code, self.response.reason))
            logger.debug('Response: {0}'.format(self.response))

            if self.response.status_code in [404] and hunt in ['domain', 'md5', 'sha256', 'sha1']:
                return {'Message': 'Not Found in Crowd-Strike-Falcon'}

            if self.response.status_code not in [200, 201]:
                error = self.response.json()
                error_msg = error.get('errors')[0]['message']
                message = 'HTTP Status Code {0}: {1} Details:{2}'.format(self.response.status_code, self.response.reason
                                                                         , error_msg if error_msg else "None")
                logger.error(message)
                raise ConnectorError(message)
            else:
                try:
                    json_response = self.response.json()
                    logger.debug('Response: {0}'.format(json_response))
                    if json_response:
                        return json_response
                    else:
                        logger.error('No Response.')
                        raise ConnectorError('No Response.')
                except:
                    return self.response.content

        except requests.exceptions.SSLError:
            logger.error('An SSL error occurred.')
            raise ConnectorError('An SSL error occurred.')
        except requests.exceptions.ConnectionError:
            logger.error('A connection error occurred.')
            raise ConnectorError('A connection error occurred.')
        except Exception as err:
            logger.error(err)
            raise ConnectorError(err)

    # ----- oauth2

    def generate_token(self):

        params = {'client_id': self.client_id, 'client_secret': self.client_secret}
        self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        resp = self.api_request('/oauth2/token', verb='POST', data=params)

        if resp:
            self.access_token = resp['access_token']
            self.headers['Authorization'] = 'Bearer {0}'.format(self.access_token)
            self.headers['Content-Type'] = 'application/json'

    # ----- real-time-response session

    def session_initialize(self, device_id):
        try:
            self.device_id = device_id
            params = {
                'device_id': self.device_id,
                'origin': 'RTR'
            }
            if self.queue_offline:
                params['queue_offline'] = True
            else:
                params['queue_offline'] = False

            json_data = self.api_request('/real-time-response/entities/sessions/v1', verb='POST', json_data=params)

            if json_data['resources']:

                self.session_id = json_data['resources'][0]['session_id']

                for cmd in json_data['resources'][0]['scripts']:
                    if not cmd['command'] in self.cmds_available:
                        self.cmds_available.append(cmd['command'])

                    self.cmds_help[cmd['command']] = cmd

                # Add session_refresh timer hook
                self.session_refresh()

            else:
                logger.info('{0}'.format(json_data['errors']))

            return json_data
        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def session_metadata(self):

        params = {
            'ids': [
                self.session_id
            ]
        }

        return self.api_request('/real-time-response/entities/sessions/v1', verb='POST', json_data=params)

    def session_list(self):

        return self.api_request('/real-time-response/queries/sessions/v1', verb='GET')

    def session_delete(self, session_id=None):

        # Delete timer for session refresh
        self.timer.cancel()

        if session_id:
            param = {'session_id': session_id}
        else:
            param = {'session_id': self.session_id}

        return self.api_request('/real-time-response/entities/sessions/v1', verb='DELETE', params=param)

    def session_refresh(self, device_id=None):

        # Add timer every 5 minutes to refresh the session to maintain connection
        self.timer = threading.Timer(300, self.session_refresh)
        self.timer.start()
        logger.debug('Session Refresh called.')

        if device_id:
            params = {'device_id': device_id}
        else:
            params = {'device_id': self.device_id}

        params['origin'] = 'RTR'

        return self.api_request('/real-time-response/entities/refresh-session/v1', verb='POST', json_data=params)

    # ----- real-time-response-admin

    def admin_cmd_run(self, command=' ', args=' '):
        try:
            params = {
                'base_command': command,
                'command_string': '{0} {1}'.format(command, args),
                'device_id': self.device_id,
                'id': 0,
                'session_id': self.session_id,
            }
            # Quick Fix for data needed without quotes
            p = json.dumps(params)[:-1] + ', "persist": true}'

            json_data = self.api_request('/real-time-response/entities/admin-command/v1', verb='POST', data=p)
            return json_data

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def admin_cmd_result(self, cloud_request_id=None, sequence_id=0):
        # ToDo: Add sleep and retry if ['complete'] != 'true'
        try:
            params = {
                'cloud_request_id': cloud_request_id,
                'sequence_id': sequence_id,
            }

            json_data = self.api_request('/real-time-response/entities/admin-command/v1', verb='GET', params=params)
            return json_data

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def put_files_get(self, file_ids=[]):
        try:

            params = {'ids': file_ids}

            json_data = self.api_request('/real-time-response/entities/put-files/v1', verb='GET', params=params)
            return json_data
        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def put_files_list(self, param_dict):
        try:
            """
            :param kwargs:
            filter: FQL filter
            offset
            limit
            sort: Ex: 'created_at|asc’

            :return:
            api data
            """
            params = None
            if param_dict:
                params = param_dict

            json_data = self.api_request('/real-time-response/queries/put-files/v1', verb='GET', params=params)

            return json_data

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def scripts_get(self, file_ids=[]):
        try:
            params = {'ids': file_ids}

            json_data = self.api_request('/real-time-response/entities/scripts/v1', verb='GET', params=params)
            if json_data:
                return json_data

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def scripts_list(self, extra_params):

        try:
            """
            :param kwargs:
            filter: FQL filter
            offset
            limit
            sort: Ex: 'created_at|asc’

            :return:
            api data
            """

            params = None
            if extra_params:
                params = extra_params

            json_data = self.api_request('/real-time-response/queries/scripts/v1', verb='GET', params=params)

            if json_data:
                return json_data

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    # ----- real-time-response session-files

    def session_file_list(self, session_id=None):
        try:

            if session_id:
                params = {'session_id': session_id}

            else:
                params = {'session_id': self.session_id}

            json_data = self.api_request('/real-time-response/entities/file/v1', verb='GET', params=params)
            return json_data

        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def _upload_file_to_cyops(self, file_name, file_content, file_type):
        try:
            # Conditional import based on the FortiSOAR version.
            try:
                from integrations.crudhub import make_file_upload_request
                response = make_file_upload_request(file_name, file_content, 'application/octet-stream')

            except:
                from cshmac.requests import HmacAuth
                from integrations.crudhub import maybe_json_or_raise

                url = settings.CRUD_HUB_URL + '/api/3/files'
                auth = HmacAuth(url, 'POST', settings.APPLIANCE_PUBLIC_KEY,
                                settings.APPLIANCE_PRIVATE_KEY,
                                settings.APPLIANCE_PUBLIC_KEY.encode('utf-8'))
                files = {'file': (file_name, file_content, file_type, {'Expire': 0})}
                response = post(url, auth=auth, files=files, verify=False)
                response = maybe_json_or_raise(response)

            logger.info('File upload complete {0}'.format(str(response)))
            file_id = response['@id']
            time = datetime.datetime.now()
            file_description = 'Downloaded from CrowdStrike Falcon using connector at {time}'.format(time=time)
            attach_response = make_request('/api/3/attachments', 'POST',
                                           {'name': file_name, 'file': file_id, 'description': file_description})
            logger.info('attach file complete: {0}'.format(attach_response))
            return attach_response
        except Exception as err:
            logger.exception('An exception occurred {0}'.format(str(err)))
            raise ConnectorError('An exception occurred {0}'.format(str(err)))

    def _create_cyops_attachment(self, file_name, content, description=''):
        attachment_name = file_name
        file_resp = self._upload_file_to_cyops(attachment_name, content, 'application/octet-stream')
        return file_resp

    def session_file_download(self, sha256=None, session_id=None, target_7z=None, extra_params=None):
        """
        Get RTR extracted file contents for specified session and sha256.
        :param session_id: RTR Session id
        :param sha256: Extracted SHA256
        :param target_7z: Filename for 7zip package
        :param kwargs:
        filename: Filename to use for the archive name and the file within the archive.
        :return:
        file content
        """

        params = {}
        if session_id:
            params = {'session_id': session_id}

        else:
            params = {'session_id': self.session_id}

        params['sha256'] = sha256

        if extra_params:
            params.update(extra_params)

        self.headers['accept'] = 'application/x-7z-compressed'

        session = self.api_request('/real-time-response/entities/extracted-file-contents/v1', verb='GET', params=params)

        if target_7z == None:
            target_7z = 'CrowdStrike_Falcon_RTR.7z'

        try:
            # Upload File to CyOPs attachment module.
            attachment_response = self._create_cyops_attachment('{0}.7z'.format(target_7z),
                                                                session.content,
                                                                'File Acquisition Package from CrowdStrike Falcon RTR')

            return attachment_response
        except Exception as error:
            logger.error('Exception: {0}'.format(error))
            raise ConnectorError(str(error))

    def session_file_delete(self, ids=None, session_id=None):

        if session_id:
            params = {
                'ids': ids,
                'session_id': session_id
            }
        else:
            params = {
                'ids': ids,
                'session_id': self.session_id
            }

        return self.api_request('/real-time-response/entities/sessions/v1', verb='DELETE', params=params)

    # ----- real-time-response batch commands

    def batch_session_init(self, host_ids=[], batch_id=None, timeout=10, timeout_duration='m'):
        """
        timeout(int): default timeout is 30 seconds. Maximum is 10 minutes
        timeout_duration(str): ns, us, ms, s, m, h

        :return:
        batch_id
        """
        params = {
            'timeout': timeout,
            'timeout_duration': timeout_duration
        }
        data = {
            'host_ids': host_ids
        }
        if batch_id:
            data['existing_batch_id'] = batch_id

        json_data = self.api_request('/real-time-response/combined/batch-init-session/v1', verb='POST',
                                     params=params, json_data=data)
        return json_data

    def batch_session_refresh(self, host_ids=[], batch_id=None, timeout=10, timeout_duration='m'):
        """
        timeout(int): default timeout is 30 seconds. Maximum is 10 minutes
        timeout_duration(str): ns, us, ms, s, m, h

        :return:
        batch_id
        """
        params = {
            'timeout': timeout,
            'timeout_duration': timeout_duration
        }
        data = {
            'batch_id': self.batch_id,
        }
        if batch_id:
            data['batch_id'] = batch_id
        if host_ids:
            data['hosts_to_remove'] = host_ids

        session = self.api_request('/real-time-response/combined/batch-init-session/v1', verb='POST',
                                   params=params, json_data=data)

        return session.json().get('batch_id')

    def batch_cmd(self, command=' ', args=' ', hosts=[], batch_id=None, timeout=10, timeout_duration='m'):
        """
        Batch executes a RTR read-only command across the hosts mapped to the given batch ID.
        :param batch_id: Received from /real-time-response/combined/init-sessions/v1.
        :param command:
        :param args:
        :param hosts: If this list is supplied, only these hosts will receive the command.
        :param timeout:
        :param timeout_duration:
        :return:
        """
        params = {
            'timeout': timeout,
            'timeout_duration': timeout_duration
        }
        data = {
            'base_command': command,
            'command_string': '{0} {1}'.format(command, args),
            'batch_id': self.batch_id,
        }
        if batch_id:
            data['batch_id'] = batch_id
        if hosts:
            data['optional_hosts'] = hosts

        session = self.api_request('/real-time-response/combined/batch-command/v1', verb='POST',
                                   params=params, json_data=data)
        return session

    def batch_cmd_active_responder(self, command=' ', args=' ', hosts=[], batch_id=None, timeout=10,
                                   timeout_duration='m'):
        """
        Batch executes a RTR read-only command across the hosts mapped to the given batch ID.
        :param batch_id: Received from /real-time-response/combined/init-sessions/v1.
        :param command:
        :param args:
        :param hosts: If this list is supplied, only these hosts will receive the command.
        :param timeout:
        :param timeout_duration:
        :return:
        """
        params = {
            'timeout': timeout,
            'timeout_duration': timeout_duration
        }
        data = {
            'base_command': command,
            'command_string': '{0} {1}'.format(command, args),
            'batch_id': self.batch_id,
        }
        if batch_id:
            data['batch_id'] = batch_id
        if hosts:
            data['optional_hosts'] = hosts

        session = self.api_request('/real-time-response/combined/batch-active-responder-command/v1', verb='POST',
                                   params=params, json_data=data)
        return session

    def batch_cmd_admin(self, command=' ', args=' ', hosts=[], batch_id=None, timeout=10, timeout_duration='m'):
        """
        Batch executes a RTR read-only command across the hosts mapped to the given batch ID.
        :param batch_id: Received from /real-time-response/combined/init-sessions/v1.
        :param command:
        :param args:
        :param hosts: If this list is supplied, only these hosts will receive the command.
        :param timeout:
        :param timeout_duration:
        :return:
        """
        params = {
            'timeout': timeout,
            'timeout_duration': timeout_duration
        }
        data = {
            'base_command': command,
            'command_string': '{0} {1}'.format(command, args),
            'batch_id': self.batch_id,
        }
        if batch_id:
            data['batch_id'] = batch_id
        if hosts:
            data['optional_hosts'] = hosts

        session = self.api_request('/real-time-response/combined/batch-admin-command/v1', verb='POST',
                                   params=params, json_data=data)
        return session

    # ----- real-time-response batch-get

    def batch_get_cmd(self, file_path=None, hosts=[], batch_id=None, timeout=10, timeout_duration='m'):
        """
        timeout(int): default timeout is 30 seconds. Maximum is 10 minutes
        timeout_duration(str): ns, us, ms, s, m, h

        :return:
        batch_id
        """
        params = {
            'timeout': timeout,
            'timeout_duration': timeout_duration
        }
        data = {
            'batch_id': self.batch_id,
            'file_path': file_path,
        }
        if batch_id:
            data['batch_id'] = batch_id
        if hosts:
            data['optional_hosts'] = hosts

        session = self.api_request('/real-time-response/combined/batch-init-session/v1', verb='POST',
                                   params=params, json_data=data)

        return session

    def batch_get_result(self, req_id=None, timeout=10, timeout_duration='m'):

        params = {
            'timeout': timeout,
            'timeout_duration': timeout_duration,
            'batch_get_cmd_req_id': req_id
        }

        session = self.api_request('/real-time-response/combined/batch-init-session/v1', verb='GET', params=params)

        return session

    def check_param(self, param_value, mapping):
        updated_param_value = list(map(lambda x: x.strip(' '), param_value.split(','))) if (
                isinstance(param_value, str) and ',' in param_value) else param_value
        if isinstance(updated_param_value, list):
            if len(updated_param_value) > 1:
                updated_param_value = list(
                    map(lambda x: mapping.get(x) if x in mapping else x, updated_param_value))
                return updated_param_value
            if len(updated_param_value) == 1:
                return mapping.get(
                    updated_param_value[0]) if updated_param_value[0] in mapping else updated_param_value[0]
        return mapping.get(updated_param_value) if updated_param_value in mapping else updated_param_value

    def build_payload(self, params, mapping=PARAM_MAPPING, convert_to_list=[]):
        payload = {}
        for key, value in params.items():
            if value:
                value = self.check_param(value, mapping) if key in convert_to_list else mapping.get(
                    value) if value in mapping else value
                payload.update({key: [value] if isinstance(value, str) and key in convert_to_list else value})
        return payload

    def get_devices_ran_on(self, hash_type, hash_value, count_only):
        endpoint = '/indicators/aggregates/devices-count/v1'
        payload = {'type': hash_type, 'value': hash_value}
        logger.info('payload: {0}'.format(payload))
        device_cnt_response = self.api_request(endpoint, 'GET', params=payload, hunt=hash_type)

        try:
            resources = device_cnt_response['resources']
            device_count = resources[0].get('device_count', 0)
        except Exception as e:
            raise ConnectorError('Unable to parse response {0}'.format(e))

        if count_only:
            return {'device_count': device_count}

        if device_count <= 100:
            endpoint = '/indicators/queries/devices/v1'
            device_response = self.api_request(endpoint, 'GET', params=payload, hunt=hash_type)
            device_ids = device_response['resources']
        else:
            # Handling pagination for device response
            # by default the max limit is 100
            # if the device count is greater than 100, then we need to make additional calls to get the remaining devices
            device_gathered = 0
            device_ids = []
            while device_count > device_gathered:
                limit = 100
                offset = device_gathered
                payload = {'type': hash_type,
                        'value': hash_value,
                        'offset': str(offset),
                        'limit': str(limit)
                        }
                logger.debug('Payload ---> {0}'.format(payload))
                endpoint = '/indicators/queries/devices/v1'
                device_response = self.api_request(endpoint, 'GET', params=payload, hunt=hash_type)
                device_gathered += len(device_response['resources'])
                device_ids += device_response['resources']

        result = {'device_count': len(device_ids), 'device_ids': device_ids}
        return result


def surrender_session(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        session_id = params.get('session_id')
        f_rtr.session_id = session_id
        f_rtr.session_delete()
    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def create_session(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        device_id = params.get('device_id')
        f_rtr.session_initialize(device_id)
        return f_rtr.session_id
    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def admin_cmd_run(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        device_id = params.get('device_id')
        command = params.get('command')
        command_args = params.get('command_args')
        f_rtr.queue_offline = params.get('queue_offline')
        f_rtr.session_initialize(device_id)
        resp = f_rtr.admin_cmd_run(command, command_args)
        return resp
    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def admin_cmd_result(config, params):
    try:
        cloud_request_id = params.get('cloud_request_id')
        sequence_id = params.get('sequence_id')
        f_rtr = Falcon_RTR(config)
        return f_rtr.admin_cmd_result(cloud_request_id, sequence_id)
    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def session_file_list(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        device_id = params.get('device_id')
        f_rtr.session_initialize(device_id)
        resp = f_rtr.session_file_list(f_rtr.session_id)
        return resp
    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def session_file_download(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        device_id = params.get('device_id')
        sha256 = params.get('sha256')
        file_name = params.get('file_name')
        extra_params = params.get('extra_params')  # dict
        f_rtr.session_initialize(device_id)
        resp = f_rtr.session_file_download(sha256=sha256, target_7z=file_name, extra_params=extra_params)
        return resp
    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def scripts_list(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        params_dict = {
            'filter': params.get('filter'),
            'offset': params.get('offset'),
            'limit': params.get('limit'),
            'sort': params.get('sort')
        }
        extra_params = params.get(params_dict)  # dict
        return f_rtr.scripts_list(extra_params)

    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def scripts_get(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        file_ids = params.get('file_ids')  # List
        return f_rtr.scripts_get(file_ids)

    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def put_files_list(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        params_dict = {
            'filter': params.get('filter'),
            'offset': params.get('offset'),
            'limit': params.get('limit'),
            'sort': params.get('sort')
        }
        return f_rtr.put_files_list(params_dict)

    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def put_files_get(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        file_ids = params.get('file_ids')  # List
        return f_rtr.put_files_get(file_ids)

    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


# This is incomplete
def batch_cmd_admin(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        batch_id = params.get('batch_id')
        command = params.get('command')
        command_arg = params.get('command_arg')
        hosts = params.get('hosts')
        timeout = params.get('timeout')
        timeout_duration = params.get('timeout_duration')
        return f_rtr.batch_cmd_admin(batch_id, command, command_arg, hosts, timeout, timeout_duration.lower())

    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def show_command(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        device_id = params.get('device_id')
        f_rtr.session_initialize(device_id)
        return f_rtr.cmds_help

    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def batch_session_init(config, params):
    try:
        f_rtr = Falcon_RTR(config)
        device_id = params.get('device_id')
        f_rtr.batch_session_init(device_id)
        return f_rtr.cmds_help

    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def check_health(config):
    try:
        f_rtr = Falcon_RTR(config)
        return True

    except Exception as err:
        logger.error('{0}'.format(str(err)))
        raise ConnectorError(str(err))


def upload_ioc(config, params):
    endpoint = '/indicators/entities/iocs/v1'
    obj = Falcon_RTR(config)
    payload = obj.build_payload(params)
    resp = obj.api_request(endpoint, 'POST', data=json.dumps([payload]))
    return {'status': 'IOC uploaded successfully.', 'result': resp}


def get_ioc(config, params):
    obj = Falcon_RTR(config)
    ioc_type = params.get('ioc_type')
    ioc_value = params.get('ioc_value')
    payload = {'ids': '{0}:{1}'.format(ioc_type, ioc_value)}
    endpoint = '/indicators/entities/iocs/v1'
    resp = obj.api_request(endpoint, 'GET', params=payload)
    return {'ioc_details': resp}


def list_ioc(config, params):
    obj = Falcon_RTR(config)
    payload = obj.build_payload(params)
    logger.debug('Payload ---> {0}'.format(payload))
    data = defaultdict(list)
    list_iocs = []
    endpoint = '/indicators/queries/iocs/v1'
    while True:
        res = obj.api_request(endpoint, 'GET', params=payload)
        list_iocs.extend(res['resources'])
        offset = res['meta']['pagination']['offset']
        total = res['meta']['pagination']['total']
        if offset >= total or not offset or not total:
            break
        else:
            payload['offset'] = offset
    for ioc_info in list_iocs:
        ioc_type, ioc = ioc_info.split(':')
        data[ioc_type].append(ioc)
    summary_keys = ['ip', 'domain', 'sha1', 'md5', 'sha256']
    if data:
        data = dict(data)
        if 'ipv4' in data:
            data['ip'] = data.pop('ipv4')

        for key in summary_keys:
            if key not in data:
                data.update({'total_' + key: 0})
                continue
            data.update({'total_' + key: len(data[key])})
    data.update({'iocs_found': len(list_iocs)})
    return data


def update_ioc(config, params):
    obj = Falcon_RTR(config)
    ioc_type = params.get('type')
    ioc_value = params.get('value')
    params.pop('type')
    params.pop('value')
    endpoint = '/indicators/entities/iocs/v1'
    default_payload = {'ids': '{0}:{1}'.format(PARAM_MAPPING.get(ioc_type), ioc_value)}
    payload = obj.build_payload(params)
    resp = obj.api_request(endpoint, 'PATCH', data=json.dumps(payload), params=default_payload)
    return {'status': 'IOC updated successfully', 'result': resp}


def delete_ioc(config, params):
    obj = Falcon_RTR(config)
    ioc_type = params.get('type')
    ioc_value = params.get('value')
    payload = {'ids': ['{0}:{1}'.format(PARAM_MAPPING.get(ioc_type), ioc_value)]}
    endpoint = '/indicators/entities/iocs/v1'
    res = obj.api_request(endpoint, 'DELETE', params=payload)
    return {'status': 'IOC deleted successfully', 'result': res}


def hunt_file(config, params):
    obj = Falcon_RTR(config)
    file_hash_type = params.get('hash_type')
    file_hash_value = params.get('hash_value')
    count_only = params.get('count_only', False)
    return obj.get_devices_ran_on(PARAM_MAPPING.get(file_hash_type), file_hash_value, count_only)


def hunt_domain(config, params):
    obj = Falcon_RTR(config)
    hash_type = 'domain'
    domain_hash_value = params.get('domain_value')
    count_only = params.get('count_only', False)
    return obj.get_devices_ran_on(hash_type, domain_hash_value, count_only)


def get_list_of_processes(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/indicators/queries/processes/v1'
    result = dict()
    payload = obj.build_payload(params)
    response = obj.api_request(endpoint, 'GET', params=payload)
    result.update({'process_count': len(response['resources'])})
    result.update({'process_ids': response['resources']})
    return result


def process_details(config, params):
    obj = Falcon_RTR(config)
    payload = obj.build_payload(params)
    endpoint = '/processes/entities/processes/v1'
    res = obj.api_request(endpoint, 'GET', params=payload)
    return {'process_details': res}


def list_endpoint(config, params):
    obj = Falcon_RTR(config)
    filter_str = params.get('filter_str')
    offset = params.get('offset', 0)
    limit = params.get('limit', 100)
    endpoint = '/devices/queries/devices/v1'
    payload = {'offset': str(offset),
               'limit': str(limit),
               'filter': filter_str
               }
    logger.debug('Payload ---> {0}'.format(payload))
    response = obj.api_request(endpoint, 'GET', params=payload)
    result = dict()
    result.update({'endpoint_count': len(response['resources'])})
    result.update({'list_of_endpoints': response['resources']})
    return result


def device_details(config, params):
    obj = Falcon_RTR(config)
    payload = obj.build_payload(params)
    endpoint = '/devices/entities/devices/v2'
    res = obj.api_request(endpoint, 'GET', params=payload)
    return {'system_info': res}


def quarantine_device(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/devices/entities/devices-actions/v2?action_name=contain'
    device_ids = params.get('ids')
    if isinstance(device_ids, str):
        device_ids_list = device_ids.split(',')
    else:
        device_ids_list = device_ids
    data = json.dumps({'action_parameters': [], 'ids': device_ids_list})
    response = obj.api_request(endpoint, 'POST', data=data)
    return response


def remove_containment(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/devices/entities/devices-actions/v2?action_name=lift_containment'
    device_ids = params.get('ids')
    if isinstance(device_ids, str):
        device_ids_list = device_ids.split(',')
    else:
        device_ids_list = device_ids
    data = json.dumps({'action_parameters': [], 'ids': device_ids_list})
    response = obj.api_request(endpoint, 'POST', data=data)
    return response


def detection_search(config, params):
    logger.debug('Called detection_search : params : {0}'.format(params))
    obj = Falcon_RTR(config)
    remove_params = ['limit', 'offset', 'q', 'sort', 'filter_str']
    limit = params.get('limit')
    offset = params.get('offset')
    q = params.get('q')
    sort = params.get('sort')
    filter_str = params.get('filter_str')
    for i in remove_params:
        params.pop(i)
    querystring = {
        'filter': '',
        'limit': limit if limit else '20',
        'offset': offset if offset else '0',
        'q': q if q else '',
        'sort': PARAM_MAPPING.get(sort) if sort else 'last_behavior|desc'
    }
    query_filter = build_filter_query_params(params)
    querystring.update(
        {'filter': query_filter.rstrip('+') if not filter_str else '{0}({1})'.format(query_filter, filter_str)})
    logger.debug('querystring: {0}'.format(querystring))
    endpoint = '/detects/queries/detects/v1'
    response = obj.api_request(endpoint, 'GET', params=querystring)
    return response


def detection_aggregates(config, params):
    obj = Falcon_RTR(config)
    querystring = build_query_params(params)
    logger.debug('querystring: {0}'.format(querystring))
    endpoint = '/detects/aggregates/detects/GET/v1'
    response = obj.api_request(endpoint, 'POST', data=json.dumps([querystring]))
    return response


def build_filter_query_params(params):
    try:
        query_string = ''
        for key, value in params.items():
            value_list = []

            if value and isinstance(value, str) and value and key not in ['detection_id', 'max_confidence']:
                value = list(map(lambda x: x.strip(' '), value.split(',')))
            if isinstance(value, list):
                for i in value:
                    if i in PARAM_MAPPING:
                        value_list.append('{0}:{1}'.format(key, PARAM_MAPPING.get(i)))
                    elif i in STATUS_MAPPING:
                        value_list.append('{0}:"{1}"'.format(key, STATUS_MAPPING.get(i)))
                    else:
                        value_list.append('{0}:"{1}"'.format(key, i))
                value_filter = ','.join(value_list)
                query_string += '(' + value_filter + ')' + '+'
            elif value:
                query_string += '(' + '{key}:{value}'.format(key=key,
                                                             value=value if isinstance(value, int) else '\'{}\''.format(
                                                                 value)) + ')' + '+'
        return query_string
    except Exception as err:
        logger.error('Handle Operation Failure {0}'.format(str(err)))
        raise ConnectorError(str(err))


def build_query_params(params):
    try:
        query_params = {}
        for key, value in params.items():
            if value:
                query_params[key] = (PARAM_MAPPING.get(value) if value in PARAM_MAPPING else value) \
                    if isinstance(value, str) else value
        return query_params
    except Exception as err:
        logger.error('Handle Operation Failure {0}'.format(str(err)))
        raise ConnectorError(str(err))


def update_detection(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/detects/entities/detects/v2'
    user = params.get('uid')
    if user:
        resp = get_uid(config, params)
        user_uuid = resp.get('resources', [])
        if not user_uuid:
            raise ConnectorError('User {0} was not found'.format(params.get('uid')))
        else:
            params['assigned_to_uuid'] = user_uuid[0]
    params.pop('uid')
    payload = obj.build_payload(params, STATUS_MAPPING, convert_to_list=['ids'])
    logger.debug('payload=> {0}'.format(payload))
    response = obj.api_request(endpoint, 'PATCH', data=json.dumps(payload))
    return {'status': 'Detection state inserted successfully', 'result': response}


def get_detection_details(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/detects/entities/summaries/GET/v1'
    payload = obj.build_payload(params, convert_to_list=['ids'])
    logger.debug('payload=> {0}'.format(payload))
    response = obj.api_request(endpoint, 'POST', data=json.dumps(payload))
    return response


def list_incidents(config, params):
    obj = Falcon_RTR(config)
    filter_str = params.get('filter_str')
    offset = params.get('offset', 0)
    limit = params.get('limit', 100)
    endpoint = '/incidents/queries/incidents/v1'
    payload = {'offset': str(offset),
               'limit': str(limit),
               'filter': filter_str
               }
    logger.debug('Payload ---> {0}'.format(payload))
    response = obj.api_request(endpoint, 'GET', params=payload)
    return response


def incidents_get_crowdscores(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/incidents/combined/crowdscores/v1'
    payload = {}
    timestamp = params.get('timestamp')
    if timestamp:
        payload['timestamp'] = timestamp

    score = params.get('score')
    if score:
        payload['score'] = score
    logger.debug('payload=> {0}'.format(payload))
    response = obj.api_request(endpoint, 'GET', params=payload)
    return response


def incidents_get_details(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/incidents/entities/incidents/GET/v1'
    payload = obj.build_payload(params, convert_to_list=['ids'])
    logger.debug('payload=> {0}'.format(payload))
    response = obj.api_request(endpoint, 'POST', data=json.dumps(payload))
    return response


def incidents_query(config, params):
    obj = Falcon_RTR(config)
    filter_str = params.get('filter_str')
    offset = params.get('offset', 0)
    limit = params.get('limit', 100)
    sort = params.get('sort')
    endpoint = '/incidents/queries/incidents/v1'
    payload = {'offset': str(offset),
               'limit': str(limit)}
    if filter_str:
        payload['filter'] = filter_str
    if sort:
        payload['sort'] = sort
    logger.debug('Payload ---> {0}'.format(payload))
    response = obj.api_request(endpoint, 'GET', params=payload)
    return response


def update_incidents(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/incidents/entities/incident-actions/v1'
    status = STATUS_NUM_MAPPING.get(params.get("status"))
    if status is None:
        raise ConnectorError(f"Invalid status.")
    params = obj.build_payload(params=params, convert_to_list=["ids"])
    payload = {
        "action_parameters": [
            {
                "name": "update_status",
                "value": status
            }
        ],
        "ids": params.get("ids")
    }
    logger.debug('payload=> {0}'.format(payload))
    response = obj.api_request(endpoint, 'POST', data=json.dumps(payload))
    response = {
        "result": "Successfully updated."
    }
    return response


def get_uid(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/users/queries/user-uuids-by-email/v1'
    payload = obj.build_payload(params)
    logger.debug('payload=> {0}'.format(payload))
    response = obj.api_request(endpoint, 'GET', params=payload)
    return response


def get_user_details(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/users/entities/users/v1'
    payload = obj.build_payload(params)
    logger.debug('payload=> {0}'.format(payload))
    response = obj.api_request(endpoint, 'GET', params=payload)
    return response


def list_usernames(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/users/queries/emails-by-cid/v1'
    response = obj.api_request(endpoint, 'GET')
    return response


def list_user_id(config, params):
    obj = Falcon_RTR(config)
    endpoint = '/users/queries/user-uuids-by-cid/v1'
    response = obj.api_request(endpoint, 'GET')
    return response


operations = {
    'upload_ioc': upload_ioc,
    'get_ioc': get_ioc,
    'update_ioc': update_ioc,
    'delete_ioc': delete_ioc,
    'list_ioc': list_ioc,
    'list_endpoint': list_endpoint,
    'device_details': device_details,
    'quarantine_device': quarantine_device,
    'remove_containment': remove_containment,
    'hunt_file': hunt_file,
    'hunt_domain': hunt_domain,
    'get_list_of_processes': get_list_of_processes,
    'process_details': process_details,
    'update_detection': update_detection,
    'get_detection_details': get_detection_details,
    'detection_search': detection_search,
    'detection_aggregates': detection_aggregates,
    'get_uid': get_uid,
    'get_user_details': get_user_details,
    'list_usernames': list_usernames,
    'list_user_id': list_user_id,
    'admin_cmd_run': admin_cmd_run,
    'admin_cmd_result': admin_cmd_result,
    'session_file_list': session_file_list,
    'session_file_download': session_file_download,
    'scripts_list': scripts_list,
    'get_scripts': scripts_get,
    'put_files_list': put_files_list,
    'put_files_get': put_files_get,
    'show_command': show_command,
    'batch_session_init': batch_session_init,
    'batch_cmd_admin': batch_cmd_admin,
    'incidents_get_crowdscores': incidents_get_crowdscores,
    'incidents_get_details': incidents_get_details,
    'incidents_query': incidents_query,
    'update_incidents': update_incidents
}
