import base64
import urllib
from tlslite.utils import keyfactory
import oauth2 as oauth

class SignatureMethod_RSA_SHA1(oauth.SignatureMethod):
    name = 'RSA-SHA1'

    def signing_base(self, request, consumer, token):
        if not hasattr(request, 'normalized_url') or request.normalized_url is None:
            raise ValueError("Base URL for request is not set.")

        sig = (
            oauth.escape(request.method),
            oauth.escape(request.normalized_url),
            oauth.escape(request.get_normalized_parameters()),
        )

        key = '%s&' % oauth.escape(consumer.secret)
        if token:
            key += oauth.escape(token.secret)
        raw = '&'.join(sig)
        return key, raw

    def sign(self, request, consumer, token):
        """Builds the base signature string."""
        key, raw = self.signing_base(request, consumer, token)

        with open('./rsa/privatekey.pem', 'r') as f:
            data = f.read()
        privateKeyString = data.strip()

        privatekey = keyfactory.parsePrivateKey(privateKeyString)
        signature = privatekey.hashAndSign(raw)

        return base64.b64encode(signature)



if __name__ == "__main__":
    consumer_key = '{{consumer_key}}'
    consumer_secret = '{{consumer_secret}}'

    request_token_url = 'https://{{HOST}}/plugins/servlet/oauth/request-token'
    access_token_url = 'https://{{HOST}}//plugins/servlet/oauth/access-token'
    authorize_url = 'https://{{HOST}}//plugins/servlet/oauth/authorize'

    data_url = 'https://{{HOST}}/rest/api/2/issue/ESS-1'

    consumer = oauth.Consumer(consumer_key, consumer_secret)
    client = oauth.Client(consumer)

    # Lets try to access a JIRA issue (ESS-1). We should get a 401.
    # Checked via browser, seems to respond 404 when you don't have permission, odd but I'll change the code to pass this test
    resp, content = client.request(data_url, "GET")
    if resp['status'] != '404':
        raise Exception(resp['status'] + ": Should have no access!")

    consumer = oauth.Consumer(consumer_key, consumer_secret)
    client = oauth.Client(consumer)
    client.set_signature_method(SignatureMethod_RSA_SHA1())

    # Step 1: Get a request token. This is a temporary token that is used for
    # having the user authorize an access token and to sign the request to obtain
    # said access token.

    resp, content = client.request(request_token_url, "POST")
    # print (request_token_url)
    if resp['status'] != '200':
        raise Exception("Invalid response %s: %s" % (resp['status'],  content))

    request_token = dict((urllib.parse.parse_qsl(content)))
    request_token = { y.decode('ascii'): request_token.get(y).decode('ascii') for y in request_token.keys() }

    print ("Request Token:")
    print ("    - oauth_token        = %s" % request_token['oauth_token'])
    print ("    - oauth_token_secret = %s" % request_token['oauth_token_secret'])
    print ()

    # Step 2: Redirect to the provider. Since this is a CLI script we do not
    # redirect. In a web application you would redirect the user to the URL
    # below.

    print ("Go to the following link in your browser:")
    print ("%s?oauth_token=%s" % (authorize_url, request_token['oauth_token']))
    print ()

    # After the user has granted access to you, the consumer, the provider will
    # redirect you to whatever URL you have told them to redirect to. You can
    # usually define this in the oauth_callback argument as well.
    accepted = 'n'
    while accepted.lower() == 'n':
        accepted = input('Have you authorized me? (y/n) ')
    # oauth_verifier = raw_input('What is the PIN? ')


    # Step 3: Once the consumer has redirected the user back to the oauth_callback
    # URL you can request the access token the user has approved. You use the
    # request token to sign this request. After this is done you throw away the
    # request token and use the access token returned. You should store this
    # access token somewhere safe, like a database, for future use.
    token = oauth.Token(request_token['oauth_token'],
        request_token['oauth_token_secret'])
    #token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)
    client.set_signature_method(SignatureMethod_RSA_SHA1())

    resp, content = client.request(access_token_url, "POST")
    access_token = dict(urllib.parse.parse_qsl(content))
    access_token = { y.decode('ascii'): access_token.get(y).decode('ascii') for y in access_token.keys() }

    print ("Access Token:")
    print ("    - oauth_token        = %s" % access_token['oauth_token'])
    print ("    - oauth_token_secret = %s" % access_token['oauth_token_secret'])
    print ()
    print ("You may now access protected resources using the access tokens above.")
    print ()


    # Now lets try to access the same issue again with the access token. We should get a 200!
    accessToken = oauth.Token(access_token['oauth_token'], access_token['oauth_token_secret'])
    client = oauth.Client(consumer, accessToken)
    client.set_signature_method(SignatureMethod_RSA_SHA1())

    resp, content = client.request(data_url, "GET")
    if resp['status'] != '200':
        raise Exception("Should have access!")
