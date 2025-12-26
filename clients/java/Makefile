.PHONY: all build test clean demo

all: build

build:
	mvn package -DskipTests

test:
	mvn test

demo: build
	mvn exec:java

clean:
	mvn clean

