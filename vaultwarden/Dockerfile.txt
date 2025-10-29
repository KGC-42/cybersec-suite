FROM vaultwarden/server:latest

ENV ROCKET_PORT=8080
ENV DOMAIN=https://vaultwarden-production.up.railway.app

EXPOSE 8080