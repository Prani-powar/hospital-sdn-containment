# Build on the Ryu compatibility image already verified on the student's Mint host.
FROM hospital-ryu:lab
USER root
WORKDIR /app
COPY controller /app/controller
COPY topology /app/topology
COPY decision /app/decision
COPY configs /app/configs
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1 EVENTLET_NO_GREENDNS=yes
RUN python -c "from controller.app import HospitalController, TelemetryAPI"
RUN python -m controller.smoke_ryu
USER 65534:65534
CMD ["ryu-manager", "--ofp-listen-host", "127.0.0.1", "--ofp-tcp-listen-port", "16653", "--wsapi-host", "127.0.0.1", "--wsapi-port", "18080", "controller.app"]
