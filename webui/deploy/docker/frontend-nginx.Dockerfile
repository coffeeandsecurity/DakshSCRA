FROM node:20-alpine AS builder
WORKDIR /frontend
COPY webui/frontend/package*.json ./
RUN npm install
COPY webui/frontend/ .
RUN npm run build

FROM nginx:1.27-alpine
COPY webui/deploy/nginx/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /frontend/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
