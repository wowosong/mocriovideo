# Use the Python2.7 image
# 使用python 2.7作为基础镜像
FROM python:2.7
MAINTAINER 164644354@qq.com
# Set the working directory to /app
# 设置工作目录，作用是启动容器后直接进入的目录名称
RUN mkdir /app
WORKDIR /app 
ADD . /app 
RUN pip install -r requirements.txt && pip install uwsgi

#RUN mkdir /app
#WORKDIR /app
#ADD . /app
#COPY requirements.txt requirements.txt


# Copy the current directory contents into the container at /app
# . 表示和Dockerfile同级的目录
# 该句将当前目录下的文件复制到docker镜像的/app目录中
#ADD . /app

#EXPOSE 5000
# Install the dependencies
# 安装相关依赖
#RUN pip install -r requirements.txt
#RUN pip install uwsgi
#COPY uwsgi.ini uwsgi.ini
# run the command to start uWSGI
# 容器启动后要执行的命令 -> 启动uWSGI服务器
#RUN chmod +x uwsgi.ini
#RUN chmod +x manage.py
CMD ["uwsgi","--ini", "uwsgi.ini"]
