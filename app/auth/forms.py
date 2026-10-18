from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    """
    Login form.
    CSRF token injected automatically by Flask-WTF.
    """

    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=64)],
        render_kw={"autocomplete": "username", "id": "login-username"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=128)],
        render_kw={"autocomplete": "current-password", "id": "login-password"},
    )
    remember_me = BooleanField("Remember me", id="login-remember")
    submit = SubmitField("Sign In")
