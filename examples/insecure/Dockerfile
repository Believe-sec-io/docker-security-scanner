# Exemple volontairement vulnerable - ne pas utiliser en production.
# Ce Dockerfile declenche la majorite des regles DS-DF-*.
FROM ubuntu:18.04

MAINTAINER Believe <believe@example.com>

# Secrets en clair (DS-DF-007)
ENV DB_PASSWORD=SuperSecretPassword123!
ENV API_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
ARG AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Installation sans --no-install-recommends et sans nettoyage du cache (DS-DF-004/005)
RUN apt-get update && apt-get install -y python3 python3-pip curl git openssh-server

# Script distant pipe dans un shell (DS-DF-006)
RUN curl -fsSL https://raw.githubusercontent.com/example/install.sh | sh

# Clone Git conserve et permissions dangereuses (DS-DF-010 / DS-DF-009)
RUN git clone https://github.com/example/app.git /app
RUN chmod -R 777 /app

# sudo inutile (DS-DF-011)
RUN sudo apt-get install -y telnet

# Dependances non epinglees (DS-DF-012)
RUN pip3 install requests flask
RUN npm install express lodash

# ADD d'une URL distante (DS-DF-008)
ADD https://example.com/release.tar.gz /tmp/release.tar.gz

# Ports sensibles (DS-DF-014)
EXPOSE 22 3306

# ONBUILD et CMD en forme shell (DS-DF-016)
ONBUILD RUN echo "installation de l'image derivee"
CMD /bin/bash -c "python3 /app/main.py"
