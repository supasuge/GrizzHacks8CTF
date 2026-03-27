FROM node:20-alpine

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

RUN apk add --no-cache supervisor

COPY build/package.json build/package-lock.json ./
RUN npm clean-install --omit=dev

COPY build/app.js ./app.js
COPY build/flag.txt ./flag.txt
COPY build/api-docs.html /app/api-docs.html
COPY supervisord.conf /etc/supervisord.conf

RUN mkdir -p /var/log/supervisor /var/run/supervisor \
    && chown -R node:node /app /var/log/supervisor /var/run/supervisor

USER node

EXPOSE 3000

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]