from base64 import b64encode
import json
import requests

#import beaker
from oslo_config import cfg
from oslo_log import log
import pecan
from pecan import rest

from refstack.api import constants as const
from refstack.api import utils as api_utils

LOG = log.getLogger(__name__)

OAUTH_OPTS = [
    cfg.StrOpt('access_type',
               default='online',
               help='Online or offline are possible. Indicates whether your '
                    'application needs to access an OpenStackID API when the '
                    'user is not present at the browser. This parameter '
                    'defaults to online. If your application needs to '
                    'refresh access tokens when the user is not present '
                    'at the browser, then use offline. This will result '
                    'in your application obtaining a refresh token the first '
                    'time your application exchanges an authorization code '
                    'for a user.'),
    cfg.StrOpt('approval_prompt',
               default='auto',
               help='Force or auto are possible. Indicates whether the user '
                    'should be re-prompted for consent. The default is auto, '
                    'so a given user should only see the consent page for a '
                    'given set of scopes the first time through the sequence. '
                    'If the value is force, then the user sees a consent page '
                    'even if they previously gave consent to your application '
                    'for a given set of scopes.'),
    cfg.StrOpt('client_id',
               #!!!need to be deleted in production!!!
               default='nBCRvm-6eQNzVyK~-39cu-s3-.D5jwYw.openstack.client',
#               required=True,
#               secret=True,
               help='The client ID you obtain from the OpenStackID OAUTH2 '
                    'Console when you register your app. Identifies the '
                    'client that is making the request. The value passed in '
                    'this parameter must exactly match the value shown in '
                    'the OpenStackID OAUTH2 Console.'),
    cfg.StrOpt('client_secret',
               #!!!need to be deleted in production!!!
               default='xyfL67Oi3X5ar1N-2.LXm7gj',
#               required=True,
#               secret=True,
               help='The client secret obtained during application '
                    'registration.'),
    cfg.StrOpt('grant_type',
               default='authorization_code',
               help='As defined in the OAuth 2.0 specification, this field '
                    'must contain a value of authorization_code.'),
    cfg.StrOpt('openstack_auth_server_url',
               #!!!need to be change in production
               default='https://localhost:8443',
               help='Base url for Openstack Authorization Server, '
                    'for example https://openstackid.org (including https '
                    'scheme, nd trailing \'/\').'),
    cfg.StrOpt('redirect_uri',
               #!!!need to be deleted in production!!!
               default='https://172.18.66.89:8080/v1/auth',
               help='One of the redirect_uri values registered at the '
                    'OpenStackID OAUTH2 Console.Determines where the '
                    'response is sent. The value of this parameter must '
                    'exactly match one of the values registered in the '
                    'OpenStackID OAUTH2 Console (including https scheme, '
                    'case, and trailing \'/\').'),
    cfg.StrOpt('response_type',
               default='code',
               help='Determines whether the OpenStackID OAuth 2.0 ' 
                    'endpoint returns an authorization code. Web server '
                    'applications should use code.'),
    cfg.StrOpt('scope',
               default='profile email',
               help='Space-delimited set of permissions that the application '
                    'requests. Identifies the OpenStackID API access that '
                    'your application is requesting. The values passed in '
                    'this parameter inform the consent screen that is '
                    'shown to the user.'),
]

CONF = cfg.CONF
CONF.register_opts(OAUTH_OPTS, group='oid_oauth')


class AuthController(rest.RestController):

    def _handle_auth_response(self, response):
        response = json.loads(response.text)
        error = response.get(const.ERROR)
        if error:
            LOG.debug('Error occured during request to '
                      'Openstack Authorization Server: %s' % error)
            pecan.abort(401, error)
        return response

    def _get_access_data(self, auth_code, verify_ssl):
        url = api_utils.get_openstack_token_url(auth_code)
        # forming headers
        auth_str = '%(client_id)s:%(client_secret)s' % {
            const.CLIENT_ID: CONF.oid_oauth.client_id,
            const.CLIENT_SECRET: CONF.oid_oauth.client_secret
        }
        encoded_auth_str = b64encode(auth_str)
        headers = {
            'Authorization': 'Basic %s' % encoded_auth_str,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        # request for get access token
        response = requests.post(url,
                                 headers=headers,
                                 verify=verify_ssl) 

        r = self._handle_auth_response(response)
        return r 

    def _get_user_info(self, access_data, verify_ssl):
        headers = {
            'Authorization': 'Bearer %s' % access_data[const.ACCESS_TOKEN],
            'Accept': 'application/json, text/javascript'
        }
        response = requests.get("https://localhost:8443/api/v1/users/me",
                                 headers=headers,
                                 verify=verify_ssl)
        r = self._handle_auth_response(response)
        return r
        

    @pecan.expose()
    def get(self):
#        session = pecan.request.environ['beaker.session']
        if pecan.request.GET.get(const.CODE):
            auth_code = pecan.request.GET.get(const.CODE)
            # ignore verifying the SSL certificate in app_dev_mode 
            verify_ssl = False if CONF.api.app_dev_mode else True

            access_data = self._get_access_data(auth_code, verify_ssl)
            user_info = self._get_user_info(access_data, verify_ssl)

            import pdb; pdb.set_trace()
            pecan.redirect('https://localhost:8080/')

        elif pecan.request.GET.get(const.ERROR):
            error = pecan.request.GET.get(const.ERROR)
            msg = ('Error during login to Openstack '
                   'Authorization Server: %s.' % error)
            LOG.debug(msg)
            pecan.abort(401, msg)

        else:
            # first time auth request
            #!!!fake_state
            url = api_utils.get_openstack_auth_url('fake_state')
            LOG.debug('Redirect client to Openstack Authorization Server. '
                      'Url: %s' % url)
            pecan.redirect(location=url)
