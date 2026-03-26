FROM nginx:alpine
LABEL description="nginx — event-driven, rate limiting, connection limits"
COPY nginx.conf /etc/nginx/nginx.conf
COPY www/ /usr/share/nginx/html/
EXPOSE 80
