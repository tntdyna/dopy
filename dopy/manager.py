#! /usr/bin/env python
# coding: utf-8
"""
This module simply sends request to the Digital Ocean API,
and returns their response as a dict.
"""

import requests
import json as json_module
from six import wraps

API_ENDPOINT = 'https://api.digitalocean.com/v2'


class DoError(RuntimeError):
    pass


def paginated(func):
    @wraps(func)
    def wrapper(self, url, headers=None, params=None, method='GET'):
        if method != 'GET':
            return func(self, url, headers, params, method)

        nxt = url
        out = {}

        while nxt is not None:
            result = func(self, nxt, headers, params, 'GET')
            nxt = None

            if isinstance(result, dict):
                for key, value in list(result.items()):
                    if key in out and isinstance(out[key], list):
                        out[key].extend(value)
                    else:
                        out[key] = value

                if 'links' in result \
                        and 'pages' in result['links'] \
                        and 'next' in result['links']['pages']:
                    nxt = result['links']['pages']['next']

        return out
    return wrapper


class DoManager(object):
    def __init__(self, api_key):
        self.api_endpoint = API_ENDPOINT
        self.api_key = api_key

    def all_active_droplets(self):
        json = self.request('/droplets/')
        for index in range(len(json['droplets'])):
            self.populate_droplet_ips(json['droplets'][index])
        return json['droplets']

    def new_droplet(self, name, size_id, image_id, region_id,
                    ssh_key_ids=None, virtio=True, private_networking=False,
                    backups_enabled=False, user_data=None, ipv6=False):

        params = {
            'name': str(name),
            'size': str(size_id),
            'image': str(image_id),
            'region': str(region_id),
            'virtio': str(virtio).lower(),
            'ipv6': str(ipv6).lower(),
            'private_networking': str(private_networking).lower(),
            'backups': str(backups_enabled).lower(),
        }
        if ssh_key_ids:
            # Need to be an array in v2
            if isinstance(ssh_key_ids, str):
                ssh_key_ids = [ssh_key_ids]

            if type(ssh_key_ids) == list:
                for index in range(len(ssh_key_ids)):
                    ssh_key_ids[index] = str(ssh_key_ids[index])

            params['ssh_keys'] = ssh_key_ids

        if user_data:
            params['user_data'] = user_data

        json = self.request('/droplets', params=params, method='POST')
        created_id = json['droplet']['id']
        json = self.show_droplet(created_id)
        return json

    def show_droplet(self, droplet_id):
        json = self.request('/droplets/%s' % droplet_id)
        self.populate_droplet_ips(json['droplet'])
        return json['droplet']

    def droplet_v2_action(self, droplet_id, droplet_type, params=None):
        if params is None:
            params = {}
        params['type'] = droplet_type
        json = self.request('/droplets/%s/actions' % droplet_id, params=params, method='POST')
        return json

    def reboot_droplet(self, droplet_id):
        json = self.droplet_v2_action(droplet_id, 'reboot')
        json.pop('status', None)
        return json

    def power_cycle_droplet(self, droplet_id):
        json = self.droplet_v2_action(droplet_id, 'power_cycle')
        json.pop('status', None)
        return json

    def shutdown_droplet(self, droplet_id):
        json = self.droplet_v2_action(droplet_id, 'shutdown')
        json.pop('status', None)
        return json

    def power_off_droplet(self, droplet_id):
        json = self.droplet_v2_action(droplet_id, 'power_off')
        json.pop('status', None)
        return json

    def power_on_droplet(self, droplet_id):
        json = self.droplet_v2_action(droplet_id, 'power_on')
        json.pop('status', None)
        return json

    def password_reset_droplet(self, droplet_id):
        json = self.droplet_v2_action(droplet_id, 'password_reset')
        json.pop('status', None)
        return json

    def resize_droplet(self, droplet_id, size_id):
        params = {'size': size_id}
        json = self.droplet_v2_action(droplet_id, 'resize', params)
        json.pop('status', None)
        return json

    def snapshot_droplet(self, droplet_id, name):
        params = {'name': name}
        json = self.droplet_v2_action(droplet_id, 'snapshot', params)
        json.pop('status', None)
        return json

    def restore_droplet(self, droplet_id, image_id):
        params = {'image': image_id}
        json = self.droplet_v2_action(droplet_id, 'restore', params)
        json.pop('status', None)
        return json

    def rebuild_droplet(self, droplet_id, image_id):
        params = {'image': image_id}
        json = self.droplet_v2_action(droplet_id, 'rebuild', params)
        json.pop('status', None)
        return json

    def enable_backups_droplet(self, droplet_id):
        json = self.droplet_v2_action(droplet_id, 'enable_backups')
        json.pop('status', None)
        return json

    def disable_backups_droplet(self, droplet_id):
        json = self.droplet_v2_action(droplet_id, 'disable_backups')
        json.pop('status', None)
        return json

    def rename_droplet(self, droplet_id, name):
        params = {'name': name}
        json = self.droplet_v2_action(droplet_id, 'rename', params)
        json.pop('status', None)
        return json

    def destroy_droplet(self, droplet_id, scrub_data=True):
        json = self.request('/droplets/%s' % droplet_id, method='DELETE')
        json.pop('status', None)
        return json

    def populate_droplet_ips(self, droplet):
        droplet['ip_address'] = ''
        for networkIndex in range(len(droplet['networks']['v4'])):
            network = droplet['networks']['v4'][networkIndex]
            if network['type'] == 'public':
                droplet['ip_address'] = network['ip_address']
            if network['type'] == 'private':
                droplet['private_ip_address'] = network['ip_address']

# Regions ==========================================
    def all_regions(self):
        json = self.request('/regions/')
        return json['regions']

# Images ==========================================
    def all_images(self, filter='global'):
        params = {'filter': filter}
        json = self.request('/images/', params)
        return json['images']

    def private_images(self):
        json = self.request('/images?private=true')
        return json['images']

    def image_v2_action(self, image_id, image_type, params=None):
        if params is None:
            params = {}
        params['type'] = image_type
        json = self.request('/images/%s/actions' % image_id, params=params, method='POST')
        return json

    def show_image(self, image_id):
        json = self.request('/images/%s' % image_id)
        return json['image']

    def destroy_image(self, image_id):
        self.request('/images/%s' % image_id, method='DELETE')
        return True

    def transfer_image(self, image_id, region_id):
        params = {'region': region_id}
        json = self.image_v2_action(image_id, 'transfer', params)
        json.pop('status', None)
        return json

# ssh_keys =========================================
    def all_ssh_keys(self):
        json = self.request('/account/keys')
        return json['ssh_keys']

    def new_ssh_key(self, name, pub_key):
        params = {'name': name, 'public_key': pub_key}
        json = self.request('/account/keys', params, method='POST')
        return json['ssh_key']

    def show_ssh_key(self, key_id):
        json = self.request('/account/keys/%s/' % key_id)
        return json['ssh_key']

    def edit_ssh_key(self, key_id, name, pub_key):
        params = {'name': name}  # v2 API doesn't allow to change key body now
        json = self.request('/account/keys/%s/' % key_id, params, method='PUT')
        return json['ssh_key']

    def destroy_ssh_key(self, key_id):
        self.request('/account/keys/%s' % key_id, method='DELETE')
        return True

# Sizes ============================================
    def sizes(self):
        json = self.request('/sizes/')
        return json['sizes']

# Domains ==========================================
    def all_domains(self):
        json = self.request('/domains/')
        return json['domains']

    def new_domain(self, name, ip):
        params = {
                'name': name,
                'ip_address': ip
        }
        json = self.request('/domains', params=params, method='POST')
        return json['domain']

    def show_domain(self, domain_id):
        json = self.request('/domains/%s/' % domain_id)
        return json['domain']

    def destroy_domain(self, domain_id):
        self.request('/domains/%s' % domain_id, method='DELETE')
        return True

    def all_domain_records(self, domain_id):
        json = self.request('/domains/%s/records/' % domain_id)
        return json['domain_records']

    def new_domain_record(self, domain_id, record_type, data, name=None, priority=None, port=None, weight=None):
        params = {'data': data}

        params['type'] = record_type

        if name:
            params['name'] = name
        if priority:
            params['priority'] = priority
        if port:
            params['port'] = port
        if weight:
            params['weight'] = weight

        json = self.request('/domains/%s/records/' % domain_id, params, method='POST')
        return json['domain_record']

    def show_domain_record(self, domain_id, record_id):
        json = self.request('/domains/%s/records/%s' % (domain_id, record_id))
        return json['domain_record']

    def edit_domain_record(self, domain_id, record_id, record_type, data, name=None, priority=None, port=None, weight=None):
        params = {'name': name}  # API v.2 allows only record name change
        json = self.request('/domains/%s/records/%s' % (domain_id, record_id), params, method='PUT')
        return json['domain_record']

    def destroy_domain_record(self, domain_id, record_id):
        self.request('/domains/%s/records/%s' % (domain_id, record_id), method='DELETE')
        return True

# Actions ========================
    def show_all_actions(self):
        json = self.request('/actions')
        return json['actions']

    def show_action(self, action_id):
        json = self.request('/actions/%s' % action_id)
        return json['actions']

# Floating IPs =====================================

    def all_floating_ips(self):
        """
        Lists all of the Floating IPs available on the account.
        """
        json = self.request('/floating_ips')
        return json['floating_ips']

    def new_floating_ip(self, **kwargs):
        """
        Creates a Floating IP and assigns it to a Droplet or reserves it to a region.
        """
        droplet_id = kwargs.get('droplet_id')
        region = kwargs.get('region')

        if droplet_id is not None and region is not None:
            raise DoError('Only one of droplet_id and region is required to create a Floating IP. '
                          'Set one of the variables and try again.')
        elif droplet_id is None and region is None:
            raise DoError('droplet_id or region is required to create a Floating IP. '
                          'Set one of the variables and try again.')
        else:
            if droplet_id is not None:
                params = {'droplet_id': droplet_id}
            else:
                params = {'region': region}

            json = self.request('/floating_ips', params=params, method='POST')
            return json['floating_ip']

    def destroy_floating_ip(self, ip_addr):
        """
        Deletes a Floating IP and removes it from the account.
        """
        self.request('/floating_ips/' + ip_addr, method='DELETE')

    def assign_floating_ip(self, ip_addr, droplet_id):
        """
        Assigns a Floating IP to a Droplet.
        """
        params = {'type': 'assign', 'droplet_id': droplet_id}
        json = self.request('/floating_ips/' + ip_addr + '/actions', params=params, method='POST')
        return json['action']

    def unassign_floating_ip(self, ip_addr):
        """
        Unassign a Floating IP from a Droplet.
        The Floating IP will be reserved in the region but not assigned to a Droplet.
        """
        params = {'type': 'unassign'}
        json = self.request('/floating_ips/' + ip_addr + '/actions', params=params, method='POST')
        return json['action']

    def list_floating_ip_actions(self, ip_addr):
        """
        Retrieve a list of all actions that have been executed on a Floating IP.
        """
        json = self.request('/floating_ips/' + ip_addr + '/actions')
        return json['actions']

    def get_floating_ip_action(self, ip_addr, action_id):
        """
        Retrieve the status of a Floating IP action.
        """
        json = self.request('/floating_ips/' + ip_addr + '/actions/' + action_id)
        return json['action']

# Tags =====================================
    def new_tag(self, name):
        params = {
            'name': str(name)
        }
        json = self.request('/tags', params=params, method='POST')
        return json['tag']

    def show_tag(self, name):
        json = self.request('/tags/%s' % name, method='GET')
        return json['tag']

    def all_tags(self):
        json = self.request('/tags', method='GET')
        return json['tags']

    def edit_tag(self, current_name, new_name):
        params = {
            'name': str(new_name)
        }
        json = self.request('/tags/%s' % current_name, params=params, method='PUT')
        return json['tag']

    def destroy_tag(self, name):
        json = self.request('/tags/%s' % name, method='DELETE')
        json.pop('status', None)
        return json

    def tag_resource(self, tag_name, resource_id, resource_type='droplet'):
        params = {
            'resources': [
                {
                    'resource_id': str(resource_id),
                    'resource_type': str(resource_type)
                }
            ]
        }

        json = self.request('/tags/%s/resources' % tag_name, params=params, method='POST')
        json.pop('status', None)
        return json

    def untag_resource(self, tag_name, resource_id, resource_type='droplet'):
        params = {
            'resources': [
                {
                    'resource_id': str(resource_id),
                    'resource_type': str(resource_type)
                }
            ]
        }

        json = self.request('/tags/%s/resources' % tag_name, params=params, method='DELETE')
        json.pop('status', None)
        return json

# Low Level ========================================
    def request(self, path, params={}, method='GET'):
        if not path.startswith('/'):
            path = '/'+path
        url = self.api_endpoint+path

        headers = {'Authorization': "Bearer %s" % self.api_key}
        resp = self.request_v2(url, params=params, headers=headers, method=method)

        return resp

    def request_v1(self, url, params={}, method='GET'):
        try:
            resp = requests.get(url, params=params, timeout=60)
            json = resp.json()
        except ValueError:  # requests.models.json.JSONDecodeError
            raise ValueError("The API server doesn't respond with a valid json")
        except requests.RequestException as e:  # errors from requests
            raise RuntimeError(e)

        if resp.status_code != requests.codes.ok:
            if json:
                if 'error_message' in json:
                    raise DoError(json['error_message'])
                elif 'message' in json:
                    raise DoError(json['message'])
            # The JSON reponse is bad, so raise an exception with the HTTP status
            resp.raise_for_status()
        if json.get('status') != 'OK':
            raise DoError(json['error_message'])

        return json

    def process_response(self, response):
        if response.status_code == 204:
            return {'status': response.status_code}
        else:
            return response.json()

    @paginated
    def request_v2(self, url, headers={}, params={}, method='GET'):
        headers['Content-Type'] = 'application/json'

        try:
            if method == 'POST':
                resp = requests.post(url, data=json_module.dumps(params), headers=headers, timeout=60)
                json = self.process_response(resp)
            elif method == 'DELETE':
                resp = requests.delete(url, data=json_module.dumps(params), headers=headers, timeout=60)
                json = self.process_response(resp)
            elif method == 'PUT':
                resp = requests.put(url, headers=headers, params=params, timeout=60)
                json = resp.json()
            elif method == 'GET':
                resp = requests.get(url, headers=headers, params=params, timeout=60)
                json = resp.json()
            else:
                raise DoError('Unsupported method %s' % method)

        except ValueError:  # requests.models.json.JSONDecodeError
            raise ValueError("The API server doesn't respond with a valid json")
        except requests.RequestException as e:  # errors from requests
            raise RuntimeError(e)

        if resp.status_code != requests.codes.ok:
            if json:
                if 'error_message' in json:
                    raise DoError(json['error_message'])
                elif 'message' in json:
                    raise DoError(json['message'])
            # The JSON reponse is bad, so raise an exception with the HTTP status
            resp.raise_for_status()

        if json.get('id') == 'not_found':
            raise DoError(json['message'])

        return json


if __name__ == '__main__':
    import os
    api_token = os.environ.get('DO_API_TOKEN') or os.environ['DO_API_KEY']
    do = DoManager(api_token)
    import sys
    fname = sys.argv[1]
    import pprint
    # size_id: 66, image_id: 1601, region_id: 1
    pprint.pprint(getattr(do, fname)(*sys.argv[2:]))
