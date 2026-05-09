FROM nginx:1.27-alpine

RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf

# Files in /etc/nginx/templates/*.template have ${VAR} expanded by the entrypoint at start.
COPY default.conf.template /etc/nginx/templates/default.conf.template
