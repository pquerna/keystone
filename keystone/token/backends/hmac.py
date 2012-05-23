# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import
import base64
import calendar
import copy
import datetime
import hashlib
import hmac
import json
import os

from keystone import exception
from keystone import token

# TODO: use configuration file
# TODO: allow key ID and rotation.
HMAC_SECRETS = {
    "A": "foobar"
}


class Token(token.Driver):

    def get_token(self, token_id):
        # TODO: better exceptions
        (key_id, hmac_input_b64, data_input_b64) = token_id.split(':')

        if key_id not in HMAC_SECRETS:
            raise exception.TokenNotFound(token_id=token_id)

        secret = HMAC_SECRETS[key_id]

        hmac_input = base64.urlsafe_b64decode(hmac_input_b64)
        data_input = base64.urlsafe_b64decode(data_input_b64)

        h = hmac.new(secret, digestmod=hashlib.sha1)
        h.update(data_input)
        hmac_output = h.digest()

        if hmac_output != hmac_input:
            raise exception.TokenNotFound(token_id=token_id)

        """
        At this point, the data is trusted, it was validated as untainted
        by the HMAC, however the token might still be expired....
        """
        token_ref = json.loads(data_input)

        if 'expires' not in token_ref:
            raise exception.TokenNotFound(token_id=token_id)

        token_ref['id'] = token_id
        token_ref.pop('_nonce')

        if token_ref['expires'] is not None:
            now = datetime.datetime.utcnow()

            token_ref['expires'] = datetime.datetime.fromtimestamp(
                                        token_ref['expires'])

            if token_ref['expires'] > now:
                return copy.deepcopy(token_ref)
            else:
                raise exception.TokenNotFound(token_id=token_id)
        else:
            return copy.deepcopy(token_ref)

    def create_token(self, data):
        data_copy = copy.deepcopy(data)

        key_id, secret = next(HMAC_SECRETS.iteritems())

        if 'expires' not in data:
            data_copy['expires'] = self._get_default_expire_time()

        expires_orig = data_copy['expires']

        if expires_orig is not None:
            data_copy['expires'] = calendar.timegm(expires_orig.utctimetuple())

        data_copy['_nonce'] = os.urandom(8).encode('hex').lower()

        data_out = json.dumps(data_copy)

        h = hmac.new(secret, digestmod=hashlib.sha1)
        h.update(data_out)
        hmac_output = h.digest()

        token_id = "%s:%s:%s" % (key_id,
                                 base64.urlsafe_b64encode(hmac_output),
                                 base64.urlsafe_b64encode(data_out))
        data_copy.pop('_nonce')
        data_copy['id'] = token_id
        data_copy['expires'] = expires_orig
        return (token_id, copy.deepcopy(data_copy))

    delete_token_unsupported = True

    def delete_token(self, token_id):
        """This is a no-op for the HMAC backend."""
        pass

    def list_tokens(self, user_id):
        tokens = []
        return tokens
