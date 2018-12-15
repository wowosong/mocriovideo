# encoding=utf-8
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, BooleanField, SubmitField,FileField,SelectField,SelectMultipleField
from wtforms.validators import DataRequired, Length, Required, Regexp, EqualTo, Email, ValidationError
from app.models import Admin,Tag,Auth,Role
tags=Tag.query.all()
auths=Auth.query.all()
role_list=Role.query.all()
class LoginForm(FlaskForm):
    account = StringField(label=u'账号', validators=[DataRequired(u'请输入账号')], description=u'账号', render_kw={
        "class": "form-control",
        "placeholder": u"请输入账号！",
        "required": "required"
    })
    pwd=PasswordField(label=u'密码',validators=[DataRequired(u"请输入密码")],description=u"密码",render_kw={
        "class": "form-control",
        "placeholder": u"请输入密码！",
        "required": "required"
    })
    submit=SubmitField(u'登录',render_kw={
    "class":"btn btn-primary btn-block btn-flat"
    })

    def validate_account(self,field):
        if Admin.query.filter_by(name=field.data).count()==0:
            raise ValidationError(u'账号不存在！！！')
class TagForm(FlaskForm):
    name=StringField(label=u'名称',
                     validators=[DataRequired(u'请输入标签！')],
                     description=u'标签',render_kw={
            "class":"form-control",
            "placeholder":u"请输入标签名称"
        })
    submit = SubmitField(u'添加', render_kw={
        "class": "btn btn-primary"
    })
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
    submit = SubmitField(u'保存', render_kw={
        "class": "btn btn-primary"
    })
    def validate_oldpwd(self,field):
        from flask import  session
        pwd=field.data
        name=session['admin']
        admin=Admin.query.filter_by(name=name).first()
        if   not Admin.check_password(field.data):
            raise ValidationError(u"旧密码有错！")

class MovieForm(FlaskForm):
    name = StringField(label=u'片名',
           validators=[DataRequired(u'请输入片名！')],
           description=u'片名',
           render_kw={
            "class": "form-control",
            "id":"input_title",
            "placeholder": u"请输入片名",
            "style": "width:600px;"
        })
    url=FileField(
        label=u'文件',
        validators=[DataRequired(u'请选择文件')],
        description=u'文件',
        render_kw={
            "class": "form-group",
            "placeholder": u"请选择文件"
        }
    )
    info=TextAreaField(
        label=u'简介',
        validators=[DataRequired(u'请输入简介')],
        description=u'简介',
        render_kw={
            "class": "form-control",
            "rows":"10",
            "style":"width:600px;"
        }
    )
    logo=FileField(
        label=u'封面',
        validators=[DataRequired(u'请上传封面')],
        description=u'封面',
        render_kw={
            "class": "form-control",
            "style": "width:600px;"
        }
    )
    star=SelectField(
        label=u'星级',
        validators=[DataRequired(u'请选择星级')],
        coerce=int,
        choices=[(1,u'1星级'),(2,u'2星级'),(3,u'3星级'),(4,u'4星级'),(5,u'5星级')],
        description=u'星级',
        render_kw={
            "class": "form-control",
            "style": "width:200px;"
        }
    )
    tag_id=SelectField(
        label=u'标签',
        validators=[DataRequired(u'请选择标签')],
        coerce=int,
        choices=[
            (v.id,v.name) for v in tags
        ],
        description=u'标签',
        render_kw={
            "class": "form-control",
            "style": "width:200px;"
        }
    )
    area = StringField(label=u'地区',
       validators=[DataRequired(u'请输入地区！')],
       description=u'地区',
       render_kw={
           "class": "form-control",
           "placeholder": u"请输入地区",
           "style": "width:200px;"
       })
    length = StringField(label=u'片长',
       validators=[DataRequired(u'请输入片长！')],
       description=u'片长',
       render_kw={
           "class": "form-control",
           "placeholder": u"请输入片长",
           "style": "width:200px;"
       })
    release_time = StringField(label=u'上映时间',
                         validators=[DataRequired(u'请选择上映时间！')],
                         description=u'上映时间',
                         render_kw={
                             "class": "form-control",
                             "id":"input_release_time",
                             "placeholder": u"请选择上映时间",
                             "style": "width:200px;"
                         })
    submit = SubmitField(label=u'添加', render_kw={
        "class": "btn btn-primary"
    })
class PrewForm(FlaskForm):
    name = StringField(label=u'标题',
                       validators=[DataRequired(u'请输入标题！')],
                       description=u'片名',
                       render_kw={
                           "class": "form-control",
                           "placeholder": u"请输入标题",
                           "style":"width:30%"
                       })
    info = TextAreaField(label=u'简介',
                       validators=[DataRequired(u'请输入简介！')],
                       description=u'简介',
                       render_kw={
                           "class": "form-control",
                           "placeholder": u"请输入简介",
                           "style":"width:50%",
                            "rows": "10",
                       })
    logo = FileField(
        label=u'预告封面',
        validators=[DataRequired(u'请预告封面')],
        description=u'预告封面'
    )
    submit = SubmitField(label=u'保存', render_kw={
        "class": "btn btn-primary"
    })

class AuthForm(FlaskForm):
    authName = StringField(label=u'权限',
                       validators=[DataRequired(u'请输入权限名称！')],
                       description=u'权限',
                       render_kw={
                           "class": "form-control",
                           "placeholder": u"请输入权限名称",
                           "style":"width:30%"
                       })
    authUrl = StringField(label=u'权限地址',
                       validators=[DataRequired(u'请输入权限地址！')],
                       description=u'权限地址',
                       render_kw={
                           "class": "form-control",
                           "placeholder": u"请输入权限地址",
                           "style":"width:30%"
                       })
    submit = SubmitField(label=u'保存', render_kw={
        "class": "btn btn-primary"
    })

class RoleForm(FlaskForm):
    name = StringField(label=u'角色',
                           validators=[DataRequired(u'请输入角色名称！')],
                           description=u'角色',
                           render_kw={
                               "class": "form-control",
                               "placeholder": u"请输入角色名称",
                                "style":"width:30%"
                           })
    authname = SelectMultipleField(label=u'操作权限',
                          validators=[DataRequired(u'请勾选权限！')],
                          description=u'操作权限',
                          coerce=int,
                          choices=[
                              (v.id, v.name) for v in auths
                          ],
                          render_kw={
                              "class": "form-control",
                           "style":"width:20%"
                          })
    submit = SubmitField(label=u'保存', render_kw={
        "class": "btn btn-primary"
    })


class AdminForm(FlaskForm):
    name = StringField(label=u'管理员名称',
                       validators=[DataRequired(u'请输入管理员名称！')],
                       description=u'管理员名称',
                       render_kw={
                           "class": "form-control",
                           "placeholder": u"请输入管理员名称",
                           "style":"width:30%"
                       })
    pwd = PasswordField(label=u'密码',
                       validators=[DataRequired(u'请输入密码！')],
                       description=u'密码',
                                   render_kw={
            "class": "form-control",
            "placeholder": u"请输入密码！",
            "style":"width:30%"
        })
    confirmPwd = PasswordField(label=u'确认密码',
                       validators=[DataRequired(u'请输入确认密码！'),EqualTo('pwd',message=u'密码要匹配！')],
                       description=u'确认密码', render_kw={
            "class": "form-control",
            "placeholder": u"请输入确认密码",
            "style":"width:30%"
        })
    role = SelectField(
        label=u'所属角色',
        validators=[DataRequired(u'请选择角色')],
        coerce=int,
        choices=[
            (v.id, v.name) for v in role_list
        ],
        description=u'标签',
        render_kw={
            "class": "form-control",
            "style":"width:30%"
        }
    )
    submit = SubmitField(u'保存', render_kw={
        "class": "btn btn-primary"
    })