FROM nginx:1.27-alpine

RUN rm /etc/nginx/conf.d/default.conf

# Default the listen port to 8080 — PaaS-injected PORT still wins because env
# vars set at container start override Dockerfile ENV.
ENV PORT=8080

COPY nginx.conf /etc/nginx/nginx.conf

# Files in /etc/nginx/templates/*.template have ${VAR} expanded by the entrypoint at start.
COPY default.conf.template /etc/nginx/templates/default.conf.template
