from functools import wraps

from flask import g, request
from google_jwt import GoogleJWT, VerificationFailure
from werkzeug.exceptions import Unauthorized


class FlaskGoogleJWT:
    def __init__(self, app=None):
        if app is None:
            self._google_jwt = None
        else:
            self.init_app(app)

    @property
    def google_jwt(self) -> GoogleJWT:
        if self._google_jwt is None:
            raise RuntimeError("You must call init_app before attempting to use FlaskGoogleJWT.")
        return self._google_jwt

    @property
    def google_client_id(self):
        return self.google_jwt.google_client_id

    def init_app(self, app):
        self._google_jwt = GoogleJWT(
            app.config["GOOGLE_CLIENT_ID"], app.config["GOOGLE_HOSTED_DOMAIN"]
        )

    def verify_google_token(self, token):
        return self.google_jwt.verify_google_token(token)

    def authenticate_token_header(self):
        auth_header = request.headers.get("Authorization")
        token = ""
        if auth_header:
            token = auth_header.split(" ")[1]

        if not token:
            raise Unauthorized("Provide valid auth token")

        try:
            g.jwt_payload = self.verify_google_token(token)
        except VerificationFailure as e:
            raise Unauthorized(str(e))

    def require_google_token(self, route):
        """Route decorator that requires a valid JWT token to be present in the request
        """

        @wraps(route)
        def decorator(*args, **kwargs):
            self.authenticate_token_header()
            return route(*args, **kwargs)

        return decorator
