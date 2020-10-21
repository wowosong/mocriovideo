#encoding=utf-8
from datetime import datetime
from app import db,login_manager
from  flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import check_password_hash,generate_password_hash
class User(UserMixin,db.Model):
    __tablename__="user"
    __table_args__ = {'extend_existing': True}
    id=db.Column(db.Integer,primary_key=True)#编号
    name=db.Column(db.String(100),unique=True,index=True)#昵称
    password_hash=db.Column(db.String(100))#密码
    email=db.Column(db.String(100),unique=True)#邮箱
    info=db.Column(db.Text)#个性简介
    phone=db.Column(db.String(11),unique=True)#手机号码
    face=db.Column(db.String(255),unique=True)#头像
    addtime=db.Column(db.DateTime,index=True,default=datetime.utcnow)#注册时间
    uuid=db.Column(db.String(255),unique=True)#唯一标识符
    userlog=db.relationship('UserLog',backref='user')#会员日志外键关联
    comments=db.relationship('Comment',backref='user')#评论日志外键关联
    moviecol=db.relationship('MovieCol',backref='user')#收藏电影外键关联

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
    def __repr__(self):
        return "<User:%s>"%self.name

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    @password.setter
    def generate_password(self,password):
        self.password_hash=generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.password_hash,password)
    def follow(self, movie):
        """ 关注功能 """
        if not self.is_following(movie):
            # 创建关注对象
            f = MovieCol(follower=self, user_id=self.id,movie_id=movie.id)
            db.session.add(f)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#会员登录日志
class UserLog(db.Model):
    __tablename__='userlog'
    __table_args__ = {'extend_existing': True}
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    ip=db.Column(db.String(100))#登录IP
    logontime=db.Column(db.DateTime,default=datetime.utcnow)#登录时间
    def __repr__(self):
        return  "<Userlog%s"%self.id
#标签名称
class Tag(db.Model):
    __tablename__='tag'
    __table_args__ = {'extend_existing': True}
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(100),unique=True)
    addTagTime=db.Column(db.DateTime,index=True,default=datetime.utcnow)#标签添加时间
    movies=db.relationship("Movie",backref='tag')#电影外键关系关联
    def __repr__(self):
        return "<Tag:%s>"%self.name
#电影
class Movie(db.Model):
    __tablename__='movie'
    __table_args__ = {'extend_existing': True}
    id=db.Column(db.Integer,primary_key=True)#编号
    title=db.Column(db.String(255),unique=True)#标题
    url=db.Column(db.String(255),unique=True)#地址
    info=db.Column(db.Text)#简介
    logo=db.Column(db.String(255),unique=True)#封面
    star=db.Column(db.SmallInteger)#星级
    playnum=db.Column(db.Integer)#播放量
    commentnum=db.Column(db.Integer)#评论量
    tag_id=db.Column(db.Integer,db.ForeignKey('tag.id'))#所属标签
    area=db.Column(db.String(20))#上映地区
    release_time=db.Column(db.Date)#上映时间
    length=db.Column(db.String(100))#播放时间
    addtime=db.Column(db.DateTime,index=True,default=datetime.utcnow)#添加时间
    comments = db.relationship("Comment", backref='movie')  # 电影外键关系关联
    moviecols = db.relationship("MovieCol", backref='movie')  # 收藏电影外键关系关联
    def __repr__(self):
        return  "<Movie:%r>"%self.title

class Preview(db.Model):
    __tablename__='preview'
    __table_args__ = {'extend_existing': True}
    id=db.Column(db.Integer,primary_key=True)#编号
    title=db.Column(db.String(255),unique=True)#标题
    info=db.Column(db.Text)#简介
    logo=db.Column(db.String(255),unique=True)#封面
    addtime=db.Column(db.DateTime,index=True,default=datetime.utcnow)#添加时间
    def __repr__(self):
        return "Preview:%r"%self.title
#评论
class Comment(db.Model):
    __tablename__='comment'
    __table_args__ = {'extend_existing': True}
    id=db.Column(db.Integer,primary_key=True)
    content=db.Column(db.Text)
    movie_id=db.Column(db.Integer,db.ForeignKey('movie.id'))#所属电影
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))#所属用户
    addtime = db.Column(db.DateTime, index=True, default=datetime.utcnow)  # 添加时间

    def __repr__(self):
        return "Comment:%r" % self.id
#收藏电影模型
class MovieCol(db.Model):
    __tablename__='moviecol'
    __table_args__ = {'extend_existing': True}
    id=db.Column(db.Integer,primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'))
    # 所属电影
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # 所属用户
    addtime = db.Column(db.DateTime, index=True, default=datetime.utcnow)  # 添加时间
    def __repr__(self):
        return "MovieCol:%r" % self.id
class Auth(db.Model):
    __tablename__='auth'
    __table_args__ = {'extend_existing': True}
    id=db.Column(db.String(100),primary_key=True)
    name = db.Column(db.String(100),unique=True)
    url=db.Column(db.String(255),unique=True)
    addtime=db.Column(db.DateTime,index=True,default=datetime.utcnow)
    role = db.relationship("Role", backref='auth')  # 收藏电影外键关系关联
    def __repr__(self):
        return "Auth:%r>"%self.name
#角色
class Role(db.Model):
    __tablename__='role'
    __table_args__ = {'extend_existing': True}
    id=db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(100),unique=True)
    auths=db.Column(db.String(600),db.ForeignKey('auth.id'))

    # auths=db.Column(db.String(600))
    addtime=db.Column(db.DateTime,index=True,default=datetime.utcnow)
    admins=db.relationship("Admin",backref='role')
    def __repr__(self):
        return "Role:%r>"%self.name
#管理员
class Admin(UserMixin,db.Model):
    __tablename__ = "admin"
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 昵称
    password = db.Column(db.String(100))  # 密码
    is_super=db.Column(db.SmallInteger)#是否为超级管理员，0为超级管理员
    role_id=db.Column(db.Integer,db.ForeignKey('role.id'))#所属用户
    addtime=db.Column(db.DateTime,index=True,default=datetime.utcnow)
    adminlogs=db.relationship('AdminLog',backref='admin')
    oplogs=db.relationship('OpLog',backref='admin')
    def __repr__(self):
        return "Admin:%r>" % self.name

    def __init__(self, **kwargs):
        super(Admin, self).__init__(**kwargs)
    @property
    def password_hash(self):
        raise AttributeError('password is not a readable attribute')

    # 只写属性, 设置密码
    @password_hash.setter
    def generate_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, pwd):
        return check_password_hash(self.password,pwd)
#管理员登录日志
class AdminLog(db.Model):
    __tablename__ = 'adminlog'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(100))  # 登录IP
    logontime = db.Column(db.DateTime, default=datetime.utcnow)  # 登录时间

    def __repr__(self):
        return "<Userlog%s" % self.id
#操作日志
class OpLog(db.Model):
    __tablename__='oplog'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(100))  # 登录IP
    reason=db.Column(db.String(600))#操作原因
    logontime = db.Column(db.DateTime, default=datetime.utcnow)  # 登录时间
if __name__=="__main__":
    # db.drop_all()
    db.create_all()