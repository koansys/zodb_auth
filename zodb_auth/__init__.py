import datetime

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
from colander import String
from colander import TupleSchema
from colander import deferred
from colander import null

from deform.i18n import _
from deform.widget import CheckedInputWidget
from deform.widget import CheckedPasswordWidget
from deform.widget import TextInputWidget

from limone_zodb import content_schema
from limone_zodb import content_type

from persistent import Persistent

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


email_widget = CheckedInputWidget(
    subject = "Email",
    confirm_subject = "Confirm Email",
    size = 40
    )

class Password(String):
    """
    TODO: document and test me
    TODO: figure out encoding madness
    """
    def __init__(self, encoding=None, min=None, max=None):
        self.encoding = encoding
        self.min = min
        self.max = max

    def deserialize(self, node, cstruct):
        if not cstruct:
            return null

        try:
            result = cstruct
            if not isinstance(result, unicode):
                if self.encoding:
                    result = unicode(str(cstruct), self.encoding)
                else:
                    result = unicode(cstruct)
        except Exception, e:
            raise Invalid(node,
                          _('${val} is not a string: %{err}',
                            mapping={'val':cstruct, 'err':e}))

        if self.min is not None:
            if len(result) < self.min:
                min_err = _('Shorter than minimum length ${min}',
                            mapping={'min':self.min})
                raise Invalid(node, min_err)

        if self.max is not None:
            if len(result) > self.max:
                max_err = _('Longer than maximum length ${max}',
                            mapping={'max':self.max})
                raise Invalid(node, max_err)

        import pdb; pdb.set_trace()

        return _encode_password(result)



@content_schema
class User(MappingSchema):
    userid = SchemaNode(String(),
                     title="Username",
                     description="The name of the participant",
                     validator=deferred_userid_validator)
    display_name = SchemaNode(String(), missing=null,
                              title="Display Name",
                              widget=TextInputWidget(size=40))
    email = SchemaNode(String(),
                       title="email",
                       description='Type your email address and confirm it',
                       validator=Email(),
                       widget=email_widget)
    password = SchemaNode(Password(min=6),
                          widget = CheckedPasswordWidget(size=40),
                          description = "Type your password and confirm it")
    # groups = SchemaNode(TupleSchema(),
    #                     title = "Groups",
    #                     description="The groups this user is a member of",
    #                     missing = (),
    #                     # widget = TODO: What deform widget to use?
    #                     )



def _encode_password(password):
    settings = get_settings()
    ## get this secret key from somewhere since the settings come from somewhere else
    ## return hmac.new(settings['secret'], password, sha256).hexdigest()
    return hmac.new(u'secret key that comes from somewhere not in settings',
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
    request.root['users'][user.userid] = User.deserialize(user)
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
            valid = check_password(unicode(password), user.password)
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
