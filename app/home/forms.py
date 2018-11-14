#encoding=utf-8
from flask_wtf import FlaskForm
from wtforms import  StringField,TextAreaField,PasswordField,BooleanField,SubmitField,FileField
from wtforms.validators import DataRequired,Length,Required,Regexp,EqualTo,Email,ValidationError
from app.models import User
class LoginForm(FlaskForm):
    # name = StringField(label=u'账号', validators=[DataRequired(), Regexp(
    #     '^[A-Za-z][A-Za-z0-9_.]*$', 0,
    #     u'用户名只能包括字母、数字、点、下划线')])
    name=StringField(label=u'账号',validators=[DataRequired()])
    password=PasswordField(u'密码',validators=[DataRequired()])
    remember_me = BooleanField(u'保持登录')
    submit=SubmitField(u'登录')
class RegisterForm(FlaskForm):
    name = StringField(label=u'账号',validators=[DataRequired()],render_kw={
        "class": "form-control input-lg",
        "placeholder": u"请输入账号！"
    })  # 昵称
    password = PasswordField(label=u'密码',validators=[DataRequired(),EqualTo('confirm_password',message=u'确认密码与密码必须保持一致！！')],render_kw={
        "class": "form-control input-lg",
        "placeholder": u"请输入密码！"
    })  # 密码
    confirm_password=PasswordField(label=u'确认密码',validators=[DataRequired()],render_kw={
            "class": "form-control input-lg",
            "placeholder": u"请确认密码！"
        })
    email = StringField(label=u'邮箱',validators=[DataRequired(),Length(1,64),Email(message=u'邮箱格式不对！')],render_kw={
            "class": "form-control input-lg",
            "placeholder": u"请输入邮箱！"
    }) # 邮箱
    phone = StringField(label=u'手机号码',validators=[DataRequired(),Regexp('^((1[3,5,8][0-9])|(14[5,7])|(17[0,6,7,8])|(19[7]))\\d{8}$',message=u'手机号码格式不正确')],render_kw={
        "class": "form-control input-lg",
        "placeholder": u"请输入手机号码！"
    }) # 手机号码
    submit=SubmitField(label=u'注册',render_kw={
        "class":"btn btn-lg btn-success btn-block"
    })
    def validate_name(self,field):
        if User.query.filter_by(name=field.data).first():
            raise ValidationError(u'昵称已经使用！！！')
    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(u'邮箱已经使用！！！')
    def validate_phone(self,field):
        if User.query.filter_by(phone=field.data).first():
            raise  ValidationError(u'电话号码已经使用！！！')


class UserForm(FlaskForm):
    name = StringField(label=u'昵称',
                       validators=[DataRequired(u'请输入昵称！')],
                       description=u'片名',
                       render_kw={
                           "class": "form-control",
                           "id": "input_title",
                           "placeholder": u"请输入昵称"
                       })
    email = StringField(label=u'邮箱', validators=[DataRequired(), Length(1, 64), Email(message=u'邮箱格式不对！')], render_kw={
        "class": "form-control input-lg",
        "placeholder": u"请输入邮箱！"
    })  # 邮箱
    phone = StringField(label=u'手机号码', validators=[DataRequired(),
                                                   Regexp('^((1[3,5,8][0-9])|(14[5,7])|(17[0,6,7,8])|(19[7]))\\d{8}$',
                                                          message=u'手机号码格式不正确')], render_kw={
        "class": "form-control input-lg",
        "placeholder": u"请输入手机号码！"
    })  # 手机号码
    info = TextAreaField(
        label=u'简介',
        validators=[DataRequired(u'请输入简介')],
        description=u'简介',
        render_kw={
            "class": "form-control",
            "rows": "10",
        }
    )
    logo = FileField(
        label=u'头像',
        validators=[DataRequired(u'请上传头像')],
        description=u'头像',
    )

    submit = SubmitField(label=u'保存', render_kw={
        "class": "btn btn-lg btn-success btn-block"
    })

    def validate_name(self, field):
        if User.query.filter_by(name=field.data).first():
            raise ValidationError(u'昵称已经使用！！！')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(u'邮箱已经使用！！！')

    def validate_phone(self, field):
        if User.query.filter_by(phone=field.data).first():
            raise ValidationError(u'电话号码已经使用！！！')
class PasswordForm(FlaskForm):
    oldPwd = PasswordField(label=u'旧密码',
                       validators=[DataRequired(u'请输入旧密码！'),EqualTo(u'newPwd',message=u'新旧密码要匹配！')],
                       description=u'标签',
                                   render_kw={
            "class": "form-control",
            "placeholder": u"请输入旧密码！"
        })
    newPwd = PasswordField(label=u'新密码',
                       validators=[DataRequired(u'请输入新密码！')],
                       description=u'密码', render_kw={
            "class": "form-control",
            "placeholder": u"请输入新密码"
        })
    submit = SubmitField(label=u'保存', render_kw={
        "class": "btn btn-primary"
    })
    def validate_oldpwd(self,field):
        from flask import  session
        pwd=field.data
        name=session['admin']
        admin=User.query.filter_by(name=name).first()
        if   not User.check_password(field.data):
            raise ValidationError(u"旧密码有错！")

class PostForm(FlaskForm):
        info = TextAreaField(
                label=u'评论内容',
                validators=[DataRequired(u'请输入评论内容')],
                description=u'内容',
                render_kw={
                    "id":"input_content"
                }
            )
        submit = SubmitField(label=u'提交评论', render_kw={
            "id":"btn-sub",
            "class":"btn btn-success",
            "style":"border-radius: 10px;"
        })

