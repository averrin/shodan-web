FROM ubuntu
RUN echo "Europe/Moscow" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata
EXPOSE 80
EXPOSE 443
WORKDIR /app
COPY shodan-web /app/
COPY config.yaml /app/
