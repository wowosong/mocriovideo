#encoding=utf-8
from  . import admin
from flask import  render_template,redirect,url_for,flash,session,request,abort
from app.admin.forms import LoginForm,TagForm,MovieForm,PasswordForm,PrewForm,AuthForm,RoleForm,AdminForm
from app.models import Admin,Tag,db,Movie,Preview,User,Comment,MovieCol,OpLog,AdminLog,UserLog,Auth,Role
from app import app,ALLOWED_EXTENSIONS
from functools import wraps
from werkzeug.utils import secure_filename
import os,datetime,uuid
# 上下文处理
@admin.context_processor
def tpl_extra():
    data=dict(
        online_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return  data
def admin_log_req(f):
    @wraps(f)
    def decoration_func(*args,**kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin.login',next=request.url))
        return f(*args,**kwargs)
    return decoration_func

def admin_auth(f):
    @wraps(f)
    def decoration_func(*args,**kwargs):
        admin=Admin.query.join(Role).filter(
            Role.id==Admin.role_id,
            Admin.id==session['admin_id']
        ).first()
        auths=admin.role.auths
        auths=list(map(lambda v :int(v),auths.split(",")))
        auth_list=Auth.query.all()
        urls=[v.url for v in auth_list for val in auths if val==v.id]
        rule=request.url_rule
        if str(rule) not in urls:
            abort(404)
        return f(*args,**kwargs)
    return decoration_func
@admin.route('/')
@admin_auth
def index():
    return render_template('admin/index.html')
@admin.route('/login/',methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        data=form.data
        adminUser=Admin.query.filter_by(name=data["account"]).first()
        if adminUser is not None and adminUser.check_password(data["pwd"]):
            flash(u'密码错误！','err')
            return redirect(url_for('admin.login'))
        session['admin']=data["account"]
        session['admin_id']=adminUser.id
        adminlog=AdminLog(
            admin_id=adminUser.id,
            ip=request.remote_addr,
        )
        db.session.add(adminlog)
        db.session.commit()
        return  redirect(request.args.get('next') or url_for('admin.index'))
    return render_template('admin/login.html',form=form)
@admin.route('/logout/')
@admin_log_req
def logout():
    session.pop('admin',None)
    session.pop('admin_id',None)
    return redirect(url_for('admin.login'))
@admin.route('/pwd/',methods=['GET','POST'])
@admin_log_req
def pwd():
    form=PasswordForm()
    if form.validate_on_submit():
        data=form.data
        admin=Admin.query.filter_by(name=session['admin']).first()
        from  werkzeug.security import generate_password_hash
        admin.password=generate_password_hash(data['newPwd'])
        db.session.add(admin)
        db.session.commit()
        flash(u'修改密码成功，请重新登录', 'ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'修改%s的密码' % admin.name
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.logout'))
    return render_template('admin/pwd.html',form=form)
# 添加标签
@admin.route('/tag/add',methods=['GET','POST'])
@admin_log_req
@admin_auth
def tag_add():
    form=TagForm()
    if form.validate_on_submit():
        data=form.data
        if Tag.query.filter_by(name=data['name']).count()==1:
            flash(u'标签已经存在！','err')
            return redirect(url_for('admin.tag_add'))
        tag=Tag(name=data['name'])
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'添加标签%s'%data['name']
        )
        db.session.add(tag)
        db.session.commit()
        flash(u'添加成功','ok')
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.tag_add'))
    return render_template('admin/tag_add.html',form=form)
@admin.route('/search/<int:page>')
def search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    taglist = Tag.query.filter(Tag.name.ilike('%'+key+'%')).order_by(Tag.addTagTime.desc()).paginate(page=page, per_page=5)
    return  render_template('admin/tag_list.html',taglist=taglist)

@admin.route('/tag/list/<int:page>',methods=['GET'])
@admin_log_req
@admin_auth
def tag_list(page=None):
    if page is None:
        page=1
    taglist=Tag.query.order_by(Tag.addTagTime.desc()).paginate(page=page,per_page=10)
    return render_template('admin/tag_list.html',taglist=taglist)
@admin.route('/tag/search/<int:page>')
def tag_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    taglist = Tag.query.filter(Tag.name.ilike('%'+key+'%')).order_by(Tag.addTagTime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/tag_list.html',taglist=taglist)
@admin.route('/tag/edit/<int:id>',methods=['GET','POST'])
@admin_log_req
@admin_auth
def tag_edit(id=None):
    form = TagForm()
    tag=Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        if tag.name!=data['name'] and Tag.query.filter_by(name=data['name']).count() == 1:
            flash(u'标签已经存在！', 'err')
            return redirect(url_for('admin.tag_edit',id=id))
        tag.name = data['name']
        db.session.add(tag)
        db.session.commit()
        flash(u'修改成功', 'ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'修改标签%s' % data['name']
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.tag_edit',id=id))
    return render_template('admin/tag_edit.html', form=form,tag=tag)
@admin.route('/tag/del/<int:id>',methods=['GET'])
@admin_log_req
@admin_auth
def tag_del(id=None):
    tag=Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash(u'删除标签成功','ok')
    oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'删除标签%s' % tag.name
        )
    db.session.add(oplog)
    db.session.commit()
    return redirect(url_for('admin.tag_list',page=1))
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS
def change_name(filename):
    return uuid.uuid4().hex+datetime.datetime('Y%M%D-%H%M%S')+filename
@admin.route('/movie/add',methods=['GET','POST'])
@admin_log_req
@admin_auth
def movie_add():
    form=MovieForm()
    if form.validate_on_submit():
        # file_url=secure_filename(form.url.data.filename)
        # file_logo=secure_filename(form.logo.data.filename)
        file_url=form.url.data.filename
        # print file_url,form.url
        file_logo=form.logo.data.filename
        if not os.path.exists(app.config['UP_DIR'] +'/movie/'):
            os.makedirs(app.config['UP_DIR'] +'/movie/')
            os.chmod(app.config['UP_DIR'] +'/movie/','rw')
        form.url.data.save(app.config['UP_DIR']+'/movie/'+file_url)
        form.logo.data.save(app.config['UP_DIR']+'/movie/'+file_logo)
        movie=Movie(
            title=form.data['name'],
        url =file_url,
        info = form.data['info'],
        logo =file_logo ,
        star = form.data['star'],
        playnum = 0,
        commentnum =0,
        tag_id =int( form.data['tag_id']),
        area = form.data['area'],
        release_time = form.data['release_time'],
        length=form.data['length']
        )
        db.session.add(movie)
        db.session.commit()
        # print form.url.data.filename
        flash(u'添加成功','ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'添加电影%s' % movie.title
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.movie_add'))
    return render_template('admin/movie_add.html',form=form)

@admin.route('/movie/edit/<int:id>',methods=['GET','POST'])
@admin_log_req
@admin_auth
def movie_edit(id=None):
    form=MovieForm()
    form.url.validators=[]
    form.logo.validators=[]
    movie=Movie.query.get_or_404(int(id))
    if request.method=='GET':
        form.info.data=movie.info
        form.star.data=movie.star
        form.tag_id.data=movie.tag_id
    if form.validate_on_submit():
        data=form.data
        if Movie.query.filter_by(title=data['name']).count()==1:
            flash(u'片名已经存在')
            return redirect(url_for('admin.movie_edit',id=movie.id))
        if not os.path.exists(app.config['UP_DIR'] +'/movie/'):
            os.makedirs(app.config['UP_DIR'] +'/movie/')
            os.chmod(app.config['UP_DIR']+'/movie/', 'rw')
        if form.url.data.filename!="":
            # file_url = secure_filename(form.url.data.filename)
            movie.url=form.url.data.filename
            form.url.data.save(app.config['UP_DIR'] +'/movie/'+ movie.url)
        if form.logo.data.filename != "":
            # file_logo = secure_filename(form.logo.data.filename)
            movie.logo=form.logo.data.filename
            form.logo.data.save(app.config['UP_DIR']+ '/movie/'+ movie.logo)
        movie.title=data['name']
        movie.tag_id=data['tag_id']
        movie.info=data['info']
        movie.star=data['star']
        movie.length=data['length']
        movie.area=data['area']
        movie.release_time=data['release_time']
        db.session.add(movie)
        db.session.commit()
        flash(u'修改成功','ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'修改电影%s' % movie.title
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.movie_edit',id=movie.id))
    return render_template('admin/movie_edit.html',form=form,movie=movie)

@admin.route('/movie/list/<int:page>')
@admin_log_req
@admin_auth
def movie_list(page=None):
    if page is None:
        page=1
    movie_list=Movie.query.join(Tag).filter(Tag.id==Movie.tag_id).order_by(Movie.addtime.desc()).paginate(page=page,per_page=10)
    return render_template('admin/movie_list.html',movie_list=movie_list)
@admin.route('/movie/search/<int:page>')
def movie_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    # movie = Movie.query.filter(Movie.title.ilike('%' + key + '%')).order_by(Movie.addtime.desc()).paginate(page=page,  per_page=10)
    movie_list = Movie.query.filter(Movie.title.ilike('%'+key+'%')).order_by(Movie.addtime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/movie_list.html',movie_list=movie_list)
@admin.route('/movie/del/<int:id>')
@admin_log_req
@admin_auth
def movie_del(id=None):
    movie=Movie.query.filter_by(id=id).first_or_404()
    db.session.delete(movie)
    db.session.commit()
    flash(u'删除成功','ok')
    oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'删除电影%s' % movie.title
        )
    db.session.add(oplog)
    db.session.commit()
    return redirect(url_for('admin.movie_list',page=1))
@admin.route('/preview/add',methods=['GET','POST'])
@admin_log_req
@admin_auth
def preview_add():
    form=PrewForm()
    if form.validate_on_submit():
        file_logo = form.logo.data.filename
        if not os.path.exists(app.config['UP_DIR']+'/preview/'):
            os.makedirs(app.config['UP_DIR']+'/preview/')
            os.chmod(app.config['UP_DIR']+'/preview/', 'rw')
        form.logo.data.save(app.config['UP_DIR']+'/preview/' + file_logo)
        preview = Preview(
            title=form.data['name'],
            logo=file_logo,
            info=form.data['info'])
        db.session.add(preview)
        db.session.commit()
        flash(u'操作成功','ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'添加预告%s' % preview.title
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.preview_add'))
    return render_template('admin/preview_add.html',form=form)
@admin.route('/preview/edit/<int:id>',methods=['GET','POST'])
@admin_log_req
@admin_auth
def preview_edit(id=None):
    form=PrewForm()
    preview = Preview.query.get_or_404(int(id))
    # form.logo.validators=[]
    if form.validate_on_submit():
        file_logo = form.logo.data.filename
        if not os.path.exists(app.config['UP_DIR']+'/preview/'):
            os.makedirs(app.config['UP_DIR']+'/preview/')
            os.chmod(app.config['UP_DIR']+'/preview/', 'rw')
        # form.logo.data.save(app.config['UP_DIR'] + file_logo)
        if form.logo.data.filename != "":
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = file_logo
            form.logo.data.save(app.config['UP_DIR']+'/preview/' + preview.logo)
        preview.title = form.data['name']
        preview.logo = form.data['logo']
        preview.info = form.data['info']
        db.session.add(preview)
        db.session.commit()
        flash(u'操作成功','ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'修改预告%s' % preview.title
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.preview_edit',id=preview.id))
    return render_template('admin/preview_edit.html',form=form,preview=preview)
@admin.route('/preview/list/<int:page>')
@admin_log_req
@admin_auth
def preview_list(page=None):
    if page is None:
        page = 1
    prew_list = Preview.query.filter().order_by(Preview.addtime.desc()).paginate(
        page=page, per_page=10)
    return render_template('admin/preview_list.html',prew_list=prew_list)
@admin.route('/preview/search/<int:page>')
def preview_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    prew_list = Preview.query.filter(Preview.title.ilike('%'+key+'%')).order_by(Preview.addtime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/preview_list.html',prew_list=prew_list)
@admin.route('/preview/del/<int:id>')
@admin_log_req
def preview_del(id=None):
    prew=Preview.query.filter_by(id=id).first_or_404()
    db.session.delete(prew)
    db.session.commit()
    flash(u'删除成功','ok')
    oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'删除预告%s' % prew.title
        )
    db.session.add(oplog)
    db.session.commit()
    return redirect(url_for('admin.preview_list',page=1))
@admin.route('/user/list/<int:page>',methods=['GET'])
@admin_log_req
@admin_auth
def user_list(page=None):
    if page is None:
        page = 1
    user_list = User.query.filter().order_by(User.addtime.desc()).paginate(
        page=page, per_page=10)
    return render_template('admin/user_list.html',user_list=user_list)
@admin.route('/user/view/<int:id>',methods=['GET'])
@admin_auth
def user_view(id=None):
    if id is None:
        id = 1
    user = User.query.get_or_404(int(id))
    return render_template('admin/user_view.html',user=user)
@admin.route('/user/search/<int:page>')
def user_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    user_list = User.query.filter(User.name.ilike('%'+key+'%')).order_by(User.addtime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/user_list.html',user_list=user_list)
@admin.route('/user/del/<int:id>')
@admin_log_req
@admin_auth
def user_del(id=None):
    user=User.query.filter_by(id=id).first_or_404()
    db.session.delete(user)
    db.session.commit()
    flash(u'删除成功','ok')
    oplog = OpLog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason=u'删除用户%s' % user.name
    )
    db.session.add(oplog)
    db.session.commit()
    return redirect(url_for('admin.user_list',page=1))
@admin.route('/comment/list/<int:page>')
@admin_log_req
@admin_auth
def comment_list(page=None):
    if page is None:
        page=1
    comment_list=Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id==Comment.movie_id,
        User.id==Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(
        page=page, per_page=10)
    return render_template('admin/preview_comment_list.html',comment_list=comment_list)
@admin.route('/comment/del/<int:id>')
@admin_log_req
@admin_auth
def comment_del(id=None):
    comment=Comment.query.filter_by(id=id).first_or_404()
    db.session.delete(comment)
    db.session.commit()
    flash(u'删除成功','ok')
    oplog = OpLog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason=u'删除评论%s' % comment.content
    )
    db.session.add(oplog)
    db.session.commit()
    return redirect(url_for('admin.comment_list',page=1))
@admin.route('/comment/search/<int:page>')
def comment_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    comment_list = Comment.query.filter(Comment.content.ilike('%'+key+'%')).order_by(Comment.addtime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/preview_comment_list.html',comment_list=comment_list)
@admin.route('/moviecol/list/<int:page>')
@admin_log_req
@admin_auth
def moviecol_list(page=None):
    if page is None:
        page=1
    moviecol_list=MovieCol.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id==MovieCol.movie_id,
        User.id==MovieCol.user_id
    ).order_by(
        MovieCol.addtime.desc()
    ).paginate(
        page=page, per_page=10)
    return render_template('admin/moviecol_list.html',moviecol_list=moviecol_list)
@admin.route('/moviecol/search/<int:page>')
def moviecol_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    moviecol_list = MovieCol.query.join(Movie).filter(Movie.title.ilike('%'+key+'%')).order_by(MovieCol.addtime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/moviecol_list.html',moviecol_list=moviecol_list)
@admin.route('/moviecol/del/<int:id>')
@admin_log_req
@admin_auth
def moviecol_del(id=None):
    moviecol = MovieCol.query.filter_by(id=id).first_or_404()
    db.session.delete(moviecol)
    db.session.commit()
    flash(u'删除成功', 'ok')
    oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'删除电影标签%s' % moviecol.user_id
        )
    db.session.add(oplog)
    db.session.commit()
    return redirect(url_for('admin.moviecol_list', page=1))
@admin.route('/oplog/list/<int:page>')
@admin_log_req
@admin_auth
def oplog_list(page=None):
    if page is None:
        page=1
    oplog_list=OpLog.query.join(
        Admin
    ).filter(
        Admin.id==OpLog.admin_id
    ).order_by(
        OpLog.logontime.desc()
    ).paginate(
        page=page, per_page=10)
    return render_template('admin/oplog_list.html',oplog_list=oplog_list)
@admin.route('/oplog/search/<int:page>')
def oplog_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    oplog_list = OpLog.query.filter(OpLog.reason.ilike('%'+key+'%')).order_by(OpLog.logontime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/oplog_list.html',oplog_list=oplog_list)
@admin.route('/adminloginlog/list/<int:page>')
@admin_log_req
@admin_auth
def adminloginlog_list(page=None):
    if page is None:
        page = 1
    adminloginlog_list = AdminLog.query.join(
        Admin
    ).filter().order_by(AdminLog.logontime.desc()).paginate(
        page=page, per_page=10)
    return render_template('admin/adminloginlog_list.html', adminloginlog_list=adminloginlog_list)
@admin.route('/adminloginlog/search/<int:page>')
def adminloginlog_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    adminloginlog_list = AdminLog.query.join(Admin).filter(Admin.name.ilike('%'+key+'%')).order_by(AdminLog.logontime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/adminloginlog_list.html',adminloginlog_list=adminloginlog_list)
@admin.route('/userloginlog/list/<int:page>')
@admin_log_req
@admin_auth
def userloginlog_list(page=None):
    if page is None:
        page = 1
    userloginlog_list = UserLog.query.join(
        User
    ).filter(
        User.id==UserLog.user_id
    ).order_by(UserLog.logontime.desc()).paginate(
        page=page, per_page=10)
    return render_template('admin/userloginlog_list.html', userloginlog_list=userloginlog_list)
@admin.route('/userloginlog/search/<int:page>')
def userloginlog_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    userloginlog_list = UserLog.query.join(User).filter(User.name.ilike('%'+key+'%')).order_by(UserLog.logontime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/userloginlog_list.html',userloginlog_list=userloginlog_list)
@admin.route('/auth/add',methods=['GET','POST'])
@admin_log_req
@admin_auth
def auth_add():
    form=AuthForm()
    if form.validate_on_submit():
        data = form.data
        if Auth.query.filter_by(name=data['authName']).count() == 1:
            flash(u'权限已经存在！', 'err')
            return redirect(url_for('admin.auth_add'))
        auth = Auth(name=data['authName'],
                    url=data['authUrl'])
        db.session.add(auth)
        db.session.commit()
        flash(u'添加成功', 'ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'添加权限%s' % auth.name
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.auth_add'))
    return render_template('admin/auth_add.html', form=form)
@admin.route('/auth/edit/<int:id>',methods=['GET','POST'])
@admin_log_req
@admin_auth
def auth_edit(id=None):
    form=AuthForm()
    auth = Auth.query.get_or_404(int(id))
    if form.validate_on_submit():
        data = form.data
        if Auth.query.filter_by(name=data['authName']).count() == 1 and data['authName'] ==Auth.name:
            flash(u'权限已经存在！', 'err')
            return redirect(url_for('admin.auth_edit',id=auth.id))
        auth.name=data['authName']
        auth.url=data['authUrl']
        db.session.add(auth)
        db.session.commit()
        flash(u'修改成功', 'ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'修改权限%s' % auth.name
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.auth_edit',id=auth.id))
    return render_template('admin/auth_edit.html', form=form,auth=auth)
@admin.route('/auth/del/<int:id>')
@admin_log_req
@admin_auth
def auth_del(id=None):
    auth = Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash(u'删除成功', 'ok')
    oplog = OpLog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason=u'删除权限%s' % auth.name
    )
    db.session.add(oplog)
    db.session.commit()
    return redirect(url_for('admin.auth_list', page=1))
@admin.route('/auth/list/<int:page>')
@admin_log_req
@admin_auth
def auth_list(page=None):
    if page is None:
        page = 1
    auth_list = Auth.query.filter(
    ).order_by(Auth.addtime.desc()).paginate(
        page=page, per_page=10)
    return render_template('admin/auth_list.html', auth_list=auth_list)
@admin.route('/auth/search/<int:page>')
def auth_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    auth_list = Auth.query.filter(Auth.name.ilike('%'+key+'%')).order_by(Auth.addtime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/auth_list.html',auth_list=auth_list)
@admin.route('/role/add',methods=['GET','POST'])
@admin_log_req
@admin_auth
def role_add():
    form=RoleForm()
    if form.validate_on_submit():
        data = form.data
        if Role.query.filter_by(name=data['name']).count() == 1:
            flash(u'角色已经存在！', 'err')
            return redirect(url_for('admin.role_add'))
        role = Role(name=data['name'],auths =','.join(map(lambda v :str(v),data['authname'])))
        db.session.add(role)
        db.session.commit()
        flash(u'添加成功', 'ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'添加角色%s' % role.name
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.role_add'))
    return render_template('admin/role_add.html',form=form)
@admin.route('/role/list/<int:page>')
@admin_log_req
@admin_auth
def role_list(page=None):
    if page is None:
        page = 1
    role_list = Role.query.order_by(Role.addtime.desc()).paginate(
        page=page, per_page=10)
    return render_template('admin/role_list.html', role_list=role_list)
@admin.route('/role/search/<int:page>')
def role_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    role_list = Role.query.filter(Role.name.ilike('%'+key+'%')).order_by(Role.addtime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/role_list.html',role_list=role_list)
@admin.route('/role/edit/<int:id>',methods=['GET','POST'])
@admin_log_req
@admin_auth
def role_edit(id=None):
    form = RoleForm()
    role=Role.query.get_or_404(id)
    if request.method=='GET':
        auths=role.auths
        form.authname.data=list(map(lambda v:int(v),auths.split(",")))
    if form.validate_on_submit():
        data = form.data
        if role.name!=data['name'] and Role.query.filter_by(name=data['name']).count() == 1:
            flash(u'角色已经存在！', 'err')
            return redirect(url_for('admin.role_edit',id=id))
        role.name=data['name']
        role.auths=','.join(map(lambda v :str(v),data['authname']))
        db.session.add(role)
        db.session.commit()
        flash(u'修改成功', 'ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'修改权限%s' % role.name
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.role_edit',id=id))
    return render_template('admin/role_edit.html',form=form,role=role)
@admin.route('/role/del/<int:id>')
@admin_log_req
@admin_auth
def role_del(id=None):
    role = Role.query.filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash(u'删除成功', 'ok')
    return redirect(url_for('admin.role_list', page=1))
@admin.route('/admin/add',methods=['GET','POST'])
@admin_log_req
@admin_auth
def admin_add():
    form=AdminForm()
    if form.validate_on_submit():
        data = form.data
        if Admin.query.filter_by(name=data['name']).count() == 1:
            flash(u'账号已经存在！', 'err')
            return redirect(url_for('admin.admin_add'))
        adminUser = Admin(name=data['name'], role_id=data['role'],is_super=1)
        adminUser.generate_password(data['pwd'])
        db.session.add(adminUser)
        db.session.commit()
        flash(u'添加成功', 'ok')
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=u'添加管理员%s' % adminUser.name
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.admin_add'))
    return render_template('admin/admin_add.html', form=form)
@admin.route('/admin/list/<int:page>')
@admin_log_req
@admin_auth
def admin_list(page=None):
    if page is None:
        page = 1
    admin_list = Admin.query.join(
        Role
    ).filter(Admin.role_id==Role.id
    ).order_by(Admin.addtime.desc()).paginate(
        page=page, per_page=10)
    return render_template('admin/admin_list.html', admin_list=admin_list)
@admin.route('/admin/search/<int:page>')
def admin_search(page=None):
    if page is None:
        page=1
    key=request.args.get('key',"")
    admin_list = Admin.query.filter(Admin.name.ilike('%'+key+'%')).order_by(Admin.addtime.desc()).paginate(page=page, per_page=10)
    return  render_template('admin/admin_list.html',admin_list=admin_list)