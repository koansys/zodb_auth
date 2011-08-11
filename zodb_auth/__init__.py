from datetime import datetime

from hashlib import sha256
import hmac

from webob.exc import HTTPFound

from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.security import authenticated_userid
from pyramid.security import forget
from pyramid.security import remember
from pyramid.settings import get_settings
from pyramid.url import route_url
from pyramid.view import view_config

from repoze.folder import Folder

from colander import Email
from colander import Invalid
from colander import Length
from colander import MappingSchema
from colander import SchemaNode
from colander import SequenceSchema
from colander import String
from colander import Tuple
from colander import deferred
from colander import null

from deform.widget import CheckedInputWidget
from deform.widget import CheckedPasswordWidget
from deform.widget import TextInputWidget

from limone_zodb import content_schema


## TODO: get ts from settings?
TS_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


@deferred
def deferred_userid_validator(node, kw):
    request = kw['request']

    def validate_userid(node, value):
        if len(value) < 4 or len(value) > 24:
            raise Invalid(node,
                          "Length of user name must be between 4 and \
                          24 lowercase alphanumeric characters")
        if not value.replace('_', '').isalnum() or not value.islower():
            raise Invalid(node,
                          "Only lowercase numbers, letters and \
                          underscores are permitted")
        if not value[0].isalpha():
            raise Invalid(node,
                          "The username must start with a letter")
        taken = value in request.root['users']
        if taken:
            raise Invalid(node, "Username is not available")
    return validate_userid


def validate_userid(node, value):
    if len(value) < 4 or len(value) > 24:
        raise Invalid(node,
                      "Length of user name must be between 4 and \
                      24 lowercase alphanumeric characters")
    if not value.replace('_', '').isalnum() or not value.islower():
        raise Invalid(node,
                      "Only lowercase numbers, letters and \
                      underscores are permitted")
    if not value[0].isalpha():
        raise Invalid(node,
                      "The username must start with a letter")


email_widget = CheckedInputWidget(
    subject = "Email",
    confirm_subject = "Confirm Email",
    size = 40
    )


class UserSchema(MappingSchema):
    userid = SchemaNode(String(),
                        validator=validate_userid)
    display_name = SchemaNode(String(), missing=null,
                              title="Display Name",
                              widget=TextInputWidget(size=40))
    email = SchemaNode(String(),
                       title="email",
                       description='Type your email address and confirm it',
                       validator=Email(),
                       widget=email_widget)
    password = SchemaNode(String(),
                          widget = CheckedPasswordWidget(size=40),
                          description = "Type your password and confirm it",
                          validator=Length(min=6))

class Groups(SequenceSchema):
    group = SchemaNode(Tuple, missing=())

@content_schema
class User(MappingSchema):
    __acl__ = Groups(missing=())
    display_name = SchemaNode(String(), missing=null)
    email = SchemaNode(String(), validator=Email())
    last_login = SchemaNode(String(),missing=null)
    password_hmac = SchemaNode(String(),)
    userid = SchemaNode(String(),
                        validator=deferred_userid_validator)



def _encode_password(password):
    settings = get_settings()
    ## get this secret key from somewhere since the settings come from somewhere else
    ## return hmac.new(settings['secret'], password, sha256).hexdigest()
    return hmac.new('secret key that comes from somewhere not in settings',
                    password,
                    sha256).hexdigest()

def check_password(challenge_password, password):
    return _encode_password(challenge_password) == password


def includeme(config):
    """
    is there anything to resgister here? templates?
    """
    authn_policy = AuthTktAuthenticationPolicy('how-do-i-get-settings-with-jove-there?',
                                               callback=groupfinder)
    config._set_authentication_policy(authn_policy)
    config._set_authorization_policy(ACLAuthorizationPolicy())
    config.add_route('login', '/login')
    config.add_route('logout', '/logout')
    config.scan('zodb_auth', limone = config.registry.limone)


def setup_users(site, users):
    ## call this in appmaker or jove.ApplicaitonDesciptor.make_site
    site['users'] = Folder()
    uf = site['users']

    for user in users:
        uf[user['userid']] = User.deserialize(user)
        return uf[user['userid']].userid

def add_user(request, user):
    ## Just do it in the view?
    request.root['users'][user.userid] = User(**user)
    return user.userid


def groupfinder(userid, request):
    return request.root['users'][userid].groups


@view_config(route_name = 'login', renderer = "zodb_auth:login.pt")
def login(request):
    """
    """
    login_url = route_url('login', request)
    referrer = request.url
    if referrer == login_url:
        ## TODO: get the site name from somewhere
        referrer = '/tgc'
    came_from = request.params.get('came_from', referrer)
    message = login = password = ''
    if 'form.submitted' in request.params:
        login = request.params['login']
        password = request.params['password']
        user = request.root['users'].get(login, None)
        if user:
            valid = check_password(unicode(password), user.password_hmac)
            if valid:
                headers = remember(request, login)
                user.last_login = datetime.utcnow().strftime(TS_FORMAT)

                return HTTPFound(location = came_from,
                                 headers = headers)
        message = 'Login failed'

    return dict(
        came_from = came_from,
        logged_in = authenticated_userid(request),
        login = login,
        message = message,
        password = password,
        title = 'Please log in',
        action = 'login',
        )


@view_config(route_name='logout')
def logout(context, request):
    headers = forget(request)
    request.session.flash('You have been logged out.')
    return HTTPFound(location = route_url('login', request),
                     headers = headers)
