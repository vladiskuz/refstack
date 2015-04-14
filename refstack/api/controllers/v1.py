# Copyright (c) 2015 Mirantis, Inc.
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

"""Version 1 of the API."""
from oslo_config import cfg
from oslo_log import log
import pecan
from pecan import rest

from refstack import db
from refstack.api import constants as const
from refstack.api import utils as api_utils
from refstack.common import validators

#auth
from refstack.api.controllers import auth

LOG = log.getLogger(__name__)

CTRLS_OPTS = [
    cfg.IntOpt('results_per_page',
               default=20,
               help='Number of results for one page'),
    cfg.StrOpt('input_date_format',
               default='%Y-%m-%d %H:%M:%S',
               help='The format for %(start)s and %(end)s parameters' % {
                   'start': const.START_DATE,
                   'end': const.END_DATE
               })
]

CONF = cfg.CONF

CONF.register_opts(CTRLS_OPTS, group='api')


class BaseRestControllerWithValidation(rest.RestController):

    """
    Controller provides validation for POSTed data
    exposed endpoints:
    POST base_url/
    GET base_url/<item uid>
    GET base_url/schema
    """

    def __init__(self, validator):
        self.validator = validator

    def get_item(self, item_id):  # pragma: no cover
        """Handler for getting item"""
        raise NotImplemented

    def store_item(self, item_in_json):  # pragma: no cover
        """Handler for storing item. Should return new item id"""
        raise NotImplemented

    @pecan.expose('json')
    def get_one(self, arg):
        """Return test results in JSON format.
        :param arg: item ID in uuid4 format or action
        """
        if self.validator.assert_id(arg):
            return self.get_item(item_id=arg)

        elif arg == 'schema':
            return self.validator.schema

        else:
            pecan.abort(404)

    @pecan.expose('json')
    def post(self, ):
        """POST handler."""
        item = validators.safe_load_json_body(self.validator)
        item_id = self.store_item(item)
        pecan.response.status = 201
        return item_id


class ResultsController(BaseRestControllerWithValidation):

    """/v1/results handler."""

    def get_item(self, item_id):
        """Handler for getting item"""
        test_info = db.get_test(item_id)
        if not test_info:
            pecan.abort(404)
        test_list = db.get_test_results(item_id)
        test_name_list = [test_dict[0] for test_dict in test_list]
        return {"cpid": test_info.cpid,
                "created_at": test_info.created_at,
                "duration_seconds": test_info.duration_seconds,
                "results": test_name_list}

    def store_item(self, item_in_json):
        """Handler for storing item. Should return new item id"""
        test_id = db.store_results(item_in_json)
        return {'test_id': test_id}

    @pecan.expose('json')
    def get(self):
        """
            Get information of all uploaded test results in descending
            chronological order.
            Make it possible to specify some input parameters
            for filtering.
            For example:
                /v1/results?page=<page number>&cpid=1234.
            By default, page is set to page number 1,
            if the page parameter is not specified.
         """

        expected_input_params = [
            const.START_DATE,
            const.END_DATE,
            const.CPID,
        ]

        try:
            filters = api_utils.parse_input_params(expected_input_params)
            records_count = db.get_test_records_count(filters)
            page_number, total_pages_number = \
                api_utils.get_page_number(records_count)
        except api_utils.ParseInputsError as ex:
            pecan.abort(400, 'Reason: %s' % ex)
        except Exception as ex:
            LOG.debug('An error occurred: %s' % ex)
            pecan.abort(500)

        try:
            per_page = CONF.api.results_per_page
            records = db.get_test_records(page_number, per_page, filters)

            results = []
            for r in records:
                results.append({
                    'test_id': r.id,
                    'created_at': r.created_at,
                    'cpid': r.cpid
                })

            page = {}
            page['results'] = results
            page['pagination'] = {
                'current_page': page_number,
                'total_pages': total_pages_number
            }
        except Exception as ex:
            LOG.debug('An error occurred during '
                      'operation with database: %s' % ex)
            pecan.abort(400)

        return page


class V1Controller(object):

    """Version 1 API controller root."""

    results = ResultsController(validators.TestResultValidator())
    auth = auth.AuthController()
