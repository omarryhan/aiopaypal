from logging import getLogger
import datetime
import base64

import aiohttp

__all__ = ['PaypalError', 'Paypal']

logger_ = getLogger(name='Aiopaypal')
logger_.setLevel('DEBUG')


class Extensions:
    pass

class PaypalError(Exception):
    pass

class Paypal:
    def __init__(self, app, raise_for_status=True, logger=None):
        global logger_
        self.raise_for_status = raise_for_status

        # client general configs
        self.mode = app.config.CLIENT_SERVICES['paypal_v1']['mode']
        self.client_id = app.config.CLIENT_SERVICES['paypal_v1']['client_id']
        self.client_secret = app.config.CLIENT_SERVICES['paypal_v1']['client_secret']
        self.base_url = app.config.CLIENT_SERVICES['paypal_v1']['uri']
        self.merchant_id = app.config.CLIENT_SERVICES['paypal_v1']['merchant_id']
        self.email = app.config.CLIENT_SERVICES['paypal_v1']['email']

        # Append to app
        if not hasattr(app, 'exts'):
            app.exts = Extensions()
        app.exts.paypal = self
        
        # Set logger
        if logger is not None:
            logger_ = logger

        # Token response
        self.client_access_token = None
        self.client_expires_in = None
        self.client_expires_at = None
        self.app_id = None
        self.client_scope = None

        # User token
        self.user_access_token = None
        self.user_refresh_token = None
        self.user_expires_at = None
        self.user_expires_in = None
        self.user_scope = None

    #-----------Headers--------------_#

    @property
    def _client_auth_headers(self):
        if not self.client_id or not self.client_secret:
            raise PaypalError('client ID or client secret were not found')
        creds = "{}:{}".format(
            self.client_id,
            self.client_secret
        )
        token = base64.b64encode(
            creds.encode()
        ).decode().strip('\n').strip('\r')
        return dict(
            Authorization='Basic {}'.format(token)
        )

    @property
    def _client_access_headers(self):
        if self.client_access_token is not None:
            return dict(Authorization='Bearer {}'.format(self.client_access_token))
        else:
            raise PaypalError('No client access token')

    @property
    def _user_access_headers(self):
        if self.user_access_token is not None:
            return dict(Authorization='Bearer {}'.format(self.user_access_token))
        else:
            raise PaypalError('No user access token')

    #----------- Request ----------------#

    async def _request(self, method, url, base_url=None, headers=None, data=None, json=None, auth=None, as_client=True):
        # Refresh and prep headers
        await self.refresh_access(as_client)
        if headers is None:
            headers = {}
        if as_client is True:
            headers = {**headers, **self._client_access_headers}
        elif as_client is False:
            headers = {**headers, **self._user_access_headers}
        
        # Prep url
        base_url = base_url or self.base_url
        if url[0] != '/':
            url = '/' + url
        url = base_url + url

        # Send
        async with aiohttp.ClientSession(auth=auth) as sess:
            logger_.debug('>>> ' + str(url))
            async with sess.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                json=json
            ) as resp:
                # Resolve JSON
                try:
                    json_resp = await resp.json(content_type=None)
                except Exception as e:
                    logger_.error(str(e))
                    try:
                        json_resp = await resp.text()
                    except Exception as e:
                        logger_.error(str(e))
                        json_resp = {}
                
                if not json_resp:  # In case it's an empty string or list
                    json_resp = {}

                # Raise for status and log error
                if self.raise_for_status is not False:
                    try:
                        resp.raise_for_status()
                    except aiohttp.client_exceptions.ClientError as e:
                        # Debug
                        logger_.error('\n')
                        logger_.error('URL:')
                        logger_.error(str(url))
                        logger_.error('\n')
                        logger_.error('STATUS:')
                        logger_.error(str(resp.status))
                        logger_.error('\n')
                        logger_.error('HEADERS:')
                        logger_.error(str(headers))
                        logger_.error('\n')
                        logger_.error('FULL HEADERS')
                        logger_.error(resp.request_info.headers)
                        logger_.error('\n')
                        logger_.error('REQ JSON')
                        logger_.error(json)
                        logger_.error('\n')
                        logger_.error('REQ DATA')
                        logger_.error(data)
                        logger_.error('\n')
                        logger_.error('JSON:')
                        logger_.error(str(json_resp))
                        logger_.error('\n')
                        raise PaypalError(e)
                    else:
                        return json_resp
                else:
                    return json_resp
                
    async def request(self, method, url, data=None, json=None, as_client=True):
        '''
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        '''
        return await self._request(
            method=method,
            url=url,
            data=data,
            json=json,
            as_client=as_client
        )

    async def get(self, url, data=None, json=None, as_client=True):
        '''
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        '''
        return await self._request(
            method='GET',
            url=url,
            data=data,
            json=json,
            as_client=as_client
        )


    async def post(self, url, data=None, json=None, as_client=True):
        '''
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        '''
        return await self._request(
            method='POST',
            url=url,
            data=data,
            json=json,
            as_client=as_client
        )

    async def update(self, url, data=None, json=None, as_client=True):
        '''
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        '''
        return await self._request(
            method='PUT',
            url=url,
            data=data,
            json=json,
            as_client=as_client
        )


    async def delete(self, url, data=None, json=None, as_client=True):
        '''
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        '''
        return await self._request(
            method='DELETE',
            url=url,
            data=data,
            json=json,
            as_client=as_client
        )

    async def patch(self, url, data=None, json=None, as_client=True):
        '''
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        '''
        return await self._request(
            method='PATCH',
            url=url,
            data=data,
            json=json,
            as_client=as_client
        )

    async def options(self, url, data=None, json=None, as_client=True):
        '''
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        '''
        return await self._request(
            method='OPTIONS',
            url=url,
            data=data,
            json=json,
            as_client=as_client
        )
    #----------- Auth -------------#

    #----Helpers
    @property
    def is_client_access_expired(self):
        if self.client_expires_at is not None:
            return datetime.datetime.utcnow() > self.client_expires_at
        else:
            return True

    @property
    def is_user_access_expired(self):
        if self.user_expires_at is not None:
            return datetime.datetime.utcnow() > self.user_expires_at
        else:
            return True

    def _set_client_access_token(self, json_resp):
        self.client_access_token = json_resp['access_token']
        self.client_expires_in = json_resp['expires_in'] + 60  # account for clock skew
        self.client_expires_at = datetime.datetime.utcnow() + \
                          datetime.timedelta(seconds=self.client_expires_in) 
        self.app_id = json_resp['app_id']
        self.client_scope = json_resp['scope']

    def _set_user_access_token(self, json_resp): 
        self.user_access_token = json_resp['access_token']
        self.user_expires_in = json_resp['expires_in'] + 60  # account for clock skew
        self.user_expires_at = datetime.datetime.utcnow() + \
                          datetime.timedelta(seconds=self.user_expires_in) 
        self.user_scope = json_resp['scope']

    #-----Authorize
    async def authorize_client(self):
        resp = await self._request(
            method='POST',
            headers=self._client_auth_headers,
            url='/v1/oauth2/token',
            data=dict(grant_type='client_credentials'),
            as_client=None
        )
        self._set_client_access_token(resp)

    async def authorize_user(self, grant):
        args = """grant_type=authorization_code
        &response_type=token&
        redirect_uri=urn:ietf:wg:
        oauth:2.0:oob&code=""" + grant

    #-----Authentication
    async def authorization_uri(self):
        ''' https://developer.paypal.com/docs/integration/direct/identity/get-user-consent/ '''
        pass

    #------Refresh
    async def refresh_access(self, as_client=True):
        # Refresh tokens
        if as_client is True:
            if self.is_client_access_expired:
                await self.refresh_client_access()
        if as_client is False:
            if self.is_user_access_expired:
                await self.refresh_user_access()

    async def refresh_client_access(self):
        return await self.authorize_client()

    async def refresh_user_access(self):
        args = "grant_type=refresh_token&refresh_token=" + self.client_refresh_token
