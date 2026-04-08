FROM node
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash
ENV API_KEY=sk-1234567890abcdef
ENV DB_PASSWORD=hunter2
COPY . /app
EXPOSE 22 3000
CMD ["node", "app.js"]
