#encoding=utf-8
from app.home import home
from flask import  render_template,url_for,redirect,request,flash,session
from .forms import LoginForm,RegisterForm,UserForm,PasswordForm,PostForm
from flask_login import login_user,login_required,current_user,logout_user,fresh_login_required
from app.models import User,UserLog,Comment,MovieCol,Movie,Tag,Preview
from app import  db,app,login_manager,allowed_file
import os
from functools import  wraps
from werkzeug.security import generate_password_hash
import  uuid

def user_log_req(f):
    @wraps(f)
    def decoration_func(*args,**kwargs):
        if 'user' not in session:
            return redirect(url_for('home.login',next=request.url))
        return f(*args,**kwargs)
    return decoration_func
def user_log_req(f):
    @wraps(f)
    def decoration_func(*args,**kwargs):
        if 'user' not in session:
            return redirect(url_for('home.login',next=request.url))
        return f(*args,**kwargs)
    return decoration_func
@home.route('/login/',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(name=form.name.data).first()
        if user is None:
            flash(u'不存在该用户','err')
            return redirect(url_for('home.login'))
        if user is not None and not user.check_password(password=form.password.data):
            flash(u'无效密码！！！', 'err')
            return redirect(url_for('home.login'))
        login_user(user,form.remember_me.data)
        flash(u'登录成功','ok')
        session['user'] = user.name
        session['user_id'] = user.id
        userlog = UserLog(
            user_id=user.id,
            ip=request.remote_addr,
        )
        db.session.add(userlog)
        db.session.commit()
        return  redirect(request.args.get('next') or url_for('home.user'))
    return render_template('home/login.html',form=form)
@home.route('/logout')
@login_required
def logout():
    # logout_user()
    session.pop('user')
    session.pop('user_id')
    return redirect(url_for('home.login'))
@home.route('/register/',methods=['GET','POST'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        user=User(name=form.name.data,email=form.email.data,phone=form.phone.data,password_hash=form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('home.login'))
        flash(u'注册成功！！！')
    return  render_template('home/register.html',form=form)
@home.route('/user/',methods=['GET','POST'])
@login_required
@user_log_req
def user():
    form=UserForm()
    user=User.query.get(int(session.get('user_id')))
    form.logo.validators=[]
    if request.method=='GET':
        form.name.data=user.name
        form.phone.data=user.phone
        form.info.data=user.info
        form.logo.data=user.face
        form.email.data=user.email
    if form.validate_on_submit():
        print form.logo.data
        file_logo = form.logo.data.filename
        print file_logo
        if not os.path.exists(app.config['UP_DIR'] + '/userface/'):
            os.makedirs(app.config['UP_DIR'] + '/userface/')
            os.chmod(app.config['UP_DIR'] + '/userface/', 'rw')
        if file_logo and  allowed_file(file_logo.filename):
            form.logo.data.save(app.config['UP_DIR'] + '/userface/' + file_logo)
        user.info=form.data['info'],
        user.face=file_logo
        user.email=form.data['email']
        user.phone=form.data['phone']
        db.session.add(user)
        db.session.commit()
        flash(u'编辑成功', 'ok')
        session['user'] = user.name
        session['user_id'] = user.id
        userlog = UserLog(
            user_id=user.id,
            ip=request.remote_addr,
        )
        db.session.add(userlog)
        db.session.commit()
        return redirect(url_for('home.user'))
    return  render_template('home/user.html',form=form,user=user)
@home.route('/moviecol/list/<int:page>')
@login_required
@user_log_req
def moviecol(page=None):
    if page is None:
        page=1
    user = User.query.get(int(session.get('user_id')))
    moviecol_list=MovieCol.query.join(Movie).filter(MovieCol.movie_id==Movie.id,MovieCol.user_id==user.id).order_by(MovieCol.addtime.desc()).paginate(page=page,per_page=10)
    return  render_template('home/moviecol.html',moviecol_list=moviecol_list)
@home.route('/pwd/',methods=["GET","POST"])
@user_log_req
@login_required
def pwd():
    form = PasswordForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(id=session.get('user_id')).first()
        from werkzeug.security import generate_password_hash
        user.password_hash = generate_password_hash(data['newPwd'])
        db.session.add(user)
        db.session.commit()
        flash(u'修改密码成功，请重新登录', 'ok')
        oplog = UserLog(
            user_id=session.get('user_id'),
            ip=request.remote_addr
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('home.login'))
    return  render_template('home/pwd.html',form=form)
@home.route('/comments/list/<int:page>')
@login_required
@user_log_req
def comments(page=None):
    if page is None:
        page = 1
    user = User.query.get(int(session.get('user_id')))
    comments_list=Comment.query.join(User).filter(Comment.user_id==User.id,User.id==user.id).order_by(Comment.addtime.desc()).paginate(page=page,per_page=5)
    return  render_template('home/comments.html',comments_list=comments_list)
@home.route('/loginlog/list/<int:page>')
@login_required
def loginlog( page=None):
    if page is None:
        page=1
    user = User.query.get(int(session.get('user_id')))
    userlog_list=UserLog.query.join(User).filter(UserLog.user_id==User.id,User.id==user.id).order_by(UserLog.logontime.desc()).paginate(page=page,per_page=5)
    return  render_template('home/loginlog.html',userlog_list=userlog_list)
@home.route('/<int:page>/')
def index(page=None):
    if page is None:
        page=1
    movie_list=Movie.query.order_by(Movie.addtime.desc()).paginate(page=page,per_page=10)
    tag=Tag.query.order_by(Tag.addTagTime.desc())
    return  render_template('home/index.html',movie_list=movie_list,tag=tag)
@home.route('/animation/')
def animation():
    preview=Preview.query.all()
    # for p in preview:
    #     print p.logo
    return  render_template('home/animation.html',preview=preview)
@home.route('/search/<int:page>')
def search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    movie_count = Movie.query.filter(Movie.title.ilike('%'+key+'%')).count()
    movie = Movie.query.filter(Movie.title.ilike('%'+key+'%')).order_by(Movie.addtime.desc()).paginate(page=page, per_page=5)
    return  render_template('home/search.html',movie=movie,key=key,movie_count=movie_count)

@home.route('/play/<int:id>/<int:page>/',methods=['GET','POST'])
# @home.route('/play/',methods=['GET','POST'])
def play(id=None,page=None):
    if id is None:
        id=1
    if page is None:
        page = 1
    movie=Movie.query.join(Tag).filter(Tag.id==Movie.tag_id,Movie.id==int(id)).first_or_404()
    comment_count=Comment.query.filter_by(movie_id=movie.id).count()
    form = PostForm()
    if form.validate_on_submit():
    # if form.validate_on_submit():
        # print session.get('user_id')
        comment=Comment(
            content=form.data['info'],
            movie_id = movie.id,
            # 所属电影
            user_id = session.get('user_id')
            # 所属用户
        )
        movie.commentnum=comment_count+1
        db.session.add(comment)
        db.session.commit()
        flash(u'添加成功', 'ok')
        return redirect(url_for('home.play',id=movie.id,page=1))
    db.session.add(movie)
    db.session.commit()
    comment_list=Comment.query.join(Movie,User).filter(Comment.movie_id==movie.id).order_by(Comment.addtime.desc()).paginate(page=page,per_page=5)
    return  render_template('home/play.html',movie=movie,comment_list=comment_list,form=form)