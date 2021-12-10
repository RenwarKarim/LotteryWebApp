import re
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email, Length, EqualTo, ValidationError


def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"
    # Raises error if any of the excluded chars exist in the field
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(
                f"Character {char} is not allowed.")


class RegisterForm(FlaskForm):
    # validate input in fields of register form
    email = StringField(validators=[Required(), Email()])
    firstname = StringField(validators=[Required(), character_check])
    lastname = StringField(validators=[Required(), character_check])
    phone = StringField(validators=[Required()])
    password = PasswordField(validators=[Required(), Length(min=6, max=12,
                                                            message='Password must be between 6 and 12 characters in '
                                                                    'length.')])
    confirm_password = PasswordField(validators=[Required(), EqualTo('password', message='Both password fields must '
                                                                                         'be equal!')])
    pin_key = StringField(validators=[Required(), Length(min=32, max=32,
                                                         message='PIN key must be exactly 32 characters in length.')])
    submit = SubmitField(validators=[Required()])

    def validate_phone(self, phone):
        # check to see if phone number is of correct format, if not then raise error message
        p = re.compile(r'\d{4}-\d{3}-\d{4}')
        if not p.match(self.phone.data):
            raise ValidationError("Phone must be of format XXXX-XXX-XXXX (Including Dashes)")

    def validate_password(self, password):
        # check to see if password is of correct format, if not then raise error message
        p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^a-zA-Z0-9])')
        if not p.match(self.password.data):
            raise ValidationError("Password must contain at least 1 digit, 1 uppercase letter, 1 lowercase letter and "
                                  "1 special character")


class LoginForm(FlaskForm):
    # little input validation to ensure that password policy isn't revealed as this is a security risk
    email = StringField(validators=[Required(), Email()])
    password = PasswordField(validators=[Required()])
    pin = StringField(validators=[Required(), Length(min=6, max=6, message='PIN key must be exactly 6 digits in length.'
                                                     )])
    submit = SubmitField()
