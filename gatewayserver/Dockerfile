#FROM openjdk:8-jdk-alpine as builder
#FROM adoptopenjdk/openjdk8-openj9:alpine-slim
FROM adoptopenjdk/openjdk8-openj9:alpine-slim as builder

RUN  apk update && apk upgrade && apk add netcat-openbsd
WORKDIR /usr/local/gatewayserver
EXPOSE 8072
COPY target/gatewayserver-0.0.1-SNAPSHOT.jar /usr/local/gatewayserver/
COPY run.sh run.sh
RUN chmod +x run.sh
CMD ./run.sh

#Copy unpackaged application to new container
#ARG DEPENDENCY=/target/dependency
#COPY --from=build ${DEPENDENCY}/BOOT-INF/lib /app/lib
#COPY --from=build ${DEPENDENCY}/META-INF /app/META-INF
#COPY --from=build ${DEPENDENCY}/BOOT-INF/classes /app

#execute the application
#ENTRYPOINT ["java","-cp","app:app/lib/*","com.optimagrowth.gateway.ApiGatewayServerApplication"]