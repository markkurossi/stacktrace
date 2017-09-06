NAME=stacktrace:latest

VOLUMES=-v $(CURDIR)/..:/work
LINKS=

build:
	docker build -t $(NAME) .

run:
	docker run -d $(PORTS) $(VOLUMES) $(LINKS) stacktrace

shell:
	docker run --privileged -t -i $(PORTS) $(VOLUMES) $(LINKS) stacktrace /bin/bash
