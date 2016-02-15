import json
import responses
import unittest
from urlparse import urljoin
import dopy
from dopy.manager import DoError
from dopy.manager import DoManager
from dopy.manager import API_ENDPOINT


API_V2_ENDPOINT = urljoin(API_ENDPOINT, 'v2/')


forbidden_response = {
    "id": "forbidden",
    "message": "You do not have access for the attempted action.",
}

rate_limit_response = {
    "id": "too_many_requests",
    "message": "API Rate limit exceeded.",
}


error_responses = {
    403: forbidden_response,
    429: rate_limit_response,
}


class TestAllActiveDroplets(unittest.TestCase):
    def setUp(self):
        self.ins = DoManager(
            None,
            'fake_token',
        )

    @staticmethod
    def test_version():
        assert dopy.__version__ == '0.3.7a'

    @responses.activate
    def test_all_active_droplets_0(self):
        """
        Check forbidden response
        """
        responses.add(
            responses.GET,
            urljoin(API_V2_ENDPOINT, 'droplets/'),
            body=json.dumps(forbidden_response),
            status=403,
            content_type="application/json",
        )

        try:
            self.ins.all_active_droplets()
        except DoError as e:
            assert e.message == forbidden_response.get("message")


    @responses.activate
    def test_all_active_droplets_1(self):
        """
        Check reach rate limit response
        """
        responses.add(
            responses.GET,
            urljoin(API_V2_ENDPOINT, 'droplets/'),
            body=json.dumps(rate_limit_response),
            status=429,
            content_type="application/json",
        )

        try:
            self.ins.all_active_droplets()
        except DoError as e:
            assert e.message == rate_limit_response.get("message")


    @responses.activate
    def test_all_active_droplets_2(self):
        """
        Check a successful request.
        """

        test_response = open('test_samples/all_active_droplets.txt', 'r').read()
        responses.add(
            responses.GET,
            urljoin(API_V2_ENDPOINT, 'droplets/'),
            body=test_response,
            status=200,
            content_type="application/json",
        )
        result = self.ins.all_active_droplets()
        assert len(result) == 1

        instance = result[0]
        assert instance.get('status') == 'active'
        assert instance.get('ip_address') == '1.2.3.4'

    @responses.activate
    def test_all_regions(self):
        """
         Check response of getting all regions.
        """
        test_response = open('test_samples/all_regions.txt', 'r').read()
        responses.add(
            responses.GET,
            urljoin(API_V2_ENDPOINT, 'regions/'),
            body=test_response,
            status=200,
            content_type="application/json",
        )
        result = self.ins.all_regions()
        assert len(result) == 11
        assert [ i.get('name') for i in result ] == [
            u'New York 1',
            u'Amsterdam 1',
            u'San Francisco 1',
            u'New York 2',
            u'Amsterdam 2',
            u'Singapore 1',
            u'London 1',
            u'New York 3',
            u'Amsterdam 3',
            u'Frankfurt 1',
            u'Toronto 1'
        ]


    @responses.activate
    def test_all_ssh_keys(self):
        """
         Check all ssh keys
        """
        test_response = open('test_samples/all_ssh_keys.txt', 'r').read()
        responses.add(
            responses.GET,
            urljoin(API_V2_ENDPOINT, 'account/keys'),
            body=test_response,
            status=200,
            content_type="application/json",
        )
        result = self.ins.all_ssh_keys()
        assert len(result) == 2
        assert [i.get("id") for i in result] == [401185, 1439642]


    @responses.activate
    def test_others(self):
        """
         Check some other tests.
        """
        assert self.ins.api_key == 'fake_token'