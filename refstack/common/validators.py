#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

""" Validators module
"""

import binascii
import uuid

import json
import jsonschema
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

ext_format_checker = jsonschema.FormatChecker()


class ValidationError(Exception):

    def __init__(self, title, exc=None):
        super(ValidationError, self).__init__(title)
        self.exc = exc
        self.title = title
        self.details = "%s(%s: %s)" % (self.title,
                                       self.exc.__class__.__name__,
                                       str(self.exc)) \
            if self.exc else self.title

    def __repr__(self):
        return self.details

    def __str__(self):
        return self.__repr__()


def is_uuid(inst):
    """ Check that inst is a uuid_hex string. """
    try:
        uuid.UUID(hex=inst)
    except (TypeError, ValueError):
        return False
    return True


@jsonschema.FormatChecker.checks(ext_format_checker,
                                 format='uuid_hex',
                                 raises=(TypeError, ValueError))
def checker_uuid(inst):
    """Checker 'uuid_hex' format for jsonschema validator"""
    return is_uuid(inst)


class Validator(object):

    """Base class for validators"""
    def __init__(self):
        self.schema = {}  # pragma: no cover

    def validate(self, request):
        """
        :param json_data: data for validation
        """
        try:
            body = json.loads(request.body)
        except (ValueError, TypeError) as e:
            raise ValidationError('Malformed request', e)

        try:
            jsonschema.validate(body, self.schema)
        except jsonschema.ValidationError as e:
            raise ValidationError('Request doesn''t correspond to schema', e)


class TestResultValidator(Validator):

    """Validator for incoming test results."""

    def __init__(self):

        self.schema = {
            'type': 'object',
            'properties': {
                'cpid': {
                    'type': 'string'
                },
                'duration_seconds': {'type': 'integer'},
                'results': {
                    "type": "array",
                    "items": [{
                        'type': 'object',
                        'properties': {
                            'name': {'type': 'string'},
                            'uuid': {
                                'type': 'string',
                                'format': 'uuid_hex'
                            }
                        }
                    }]

                }
            },
            'required': ['cpid', 'duration_seconds', 'results'],
            'additionalProperties': False
        }
        jsonschema.Draft4Validator.check_schema(self.schema)
        self.validator = jsonschema.Draft4Validator(
            self.schema,
            format_checker=ext_format_checker
        )

    def validate(self, request):
        super(TestResultValidator, self).validate(request)
        if request.headers.get('X-Signature') or \
                request.headers.get('X-Public-Key'):
            try:
                sign = binascii.a2b_hex(request.headers.get('X-Signature', ''))
            except (binascii.Error, TypeError) as e:
                raise ValidationError('Malformed signature', e)

            try:
                key = RSA.importKey(request.headers.get('X-Public-Key', ''))
            except ValueError as e:
                raise ValidationError('Malformed public key', e)
            signer = PKCS1_v1_5.new(key)
            data_hash = SHA256.new()
            data_hash.update(request.body.encode('utf-8'))
            if not signer.verify(data_hash, sign):
                raise ValidationError('Signature verification failed')

    @staticmethod
    def assert_id(_id):
        """ Check that _id is a valid uuid_hex string. """
        return is_uuid(_id)
