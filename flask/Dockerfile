# Use the Python2.7 image
# 使用python 2.7作为基础镜像
FROM python:2.7
MAINTAINER 164644354@qq.com
# Set the working directory to /app
RUN mkdir /app
# 设置工作目录，作用是启动容器后直接进入的目录名称
WORKDIR /app
# . 表示和Dockerfile同级的目录
# 该句将当前目录下的文件复制到docker镜像的/app目录中
ADD . /app
# Install the dependencies
# 安装相关依赖
RUN pip install -r requirements.txt && pip install uwsgi

#EXPOSE 5000
# run the command to start uWSGI
# 容器启动后要执行的命令 -> 启动uWSGI服务器
#RUN chmod +x manage.py
CMD ["uwsgi","--ini", "uwsgi.ini"]
