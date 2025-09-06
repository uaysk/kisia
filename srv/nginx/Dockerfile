FROM nginx:1.21-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our main config
COPY nginx.conf /etc/nginx/nginx.conf
