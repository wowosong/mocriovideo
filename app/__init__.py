#encoding=utf-8
from flask import Flask,render_template
#激活虚拟环境
#multimovie\Scripts\activate
from  flask_sqlalchemy import SQLAlchemy
import pymysql
from flask_login import LoginManager
import os
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='mysql+pymysql://root:root@127.0.0.1:3306/movie'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=True
app.config['SECRET_KEY']='a1b32faecc8445d782899bd10733eafd'
app.config['UP_DIR']=os.path.join(os.path.abspath(os.path.dirname(__file__)),'static/uploads/')
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.debug=True
db=SQLAlchemy(app)
login_manager = LoginManager()
login_manager.session_protection = 'strong'
# 设置登陆页面的端点           蓝本名称.路由
login_manager.login_view = 'home.login'
login_manager.init_app(app)
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS
login_manager.login_message =u'请登录后访问该页面'
from .home import home as home_buleprint
from .admin import admin as admin_buleprint
app.register_blueprint(home_buleprint)
app.register_blueprint(admin_buleprint,url_prefix='/admin')

@app.errorhandler(404)
def page_not_found(error):
    return  render_template('home/404.html'),404


