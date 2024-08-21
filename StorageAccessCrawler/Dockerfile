FROM mcr.microsoft.com/playwright:v1.46.1-jammy

# Install required packages
RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip x11vnc fluxbox gnome-terminal dbus-x11 xvfb libpq-dev

# Setup unprivileged user
RUN useradd -ms /bin/bash pycrawler

# Copy into container to /pycrawler, use this as workdir and own by unprivileged user
COPY ./src/requirements.txt /pycrawler/requirements.txt

# Install python requirements
RUN python3 -m pip install -r /pycrawler/requirements.txt

# Copy into container to /pycrawler, use this as workdir and own by unprivileged user
COPY ./src /pycrawler

# Make sure the /pycrawler directory is accessible to the user
WORKDIR /pycrawler
RUN chown -R pycrawler /pycrawler

# Run as unprivileged user
USER pycrawler

# Execute entry script
ENTRYPOINT ["/bin/bash", "/pycrawler/entrypoint.sh"]
