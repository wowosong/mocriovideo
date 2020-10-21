# Use the Nginx image
# 使用Nginx镜像
FROM nginx

# Remove the default nginx.conf
# 移除官方的配置文件， 并换为自己的
RUN rm /etc/nginx/conf.d/default.conf

# Replace with our own nginx.conf
COPY nginx.conf /etc/nginx/conf.d/
