# Stage 1:
FROM eclipse-temurin:17-jdk-jammy AS builder
LABEL maintainer="Sachin Thapa <sachin@gmail.com>"

WORKDIR /app

COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn

RUN --mount=type=cache,target=/root/.m2 \
    ./mvnw dependency:copy-dependencies -B -DoutputDirectory=dependencies

COPY src src

RUN --mount=type=cache,target=/root/.m2 ./mvnw package -DskipTests

ARG CACHEBUST=1
RUN echo "Cache busted at $(date)" && ls target/


FROM tomcat:10.1.44-jre17-temurin

#RUN rm -rf \
#  ${CATALINA_HOME}/webapps/ROOT \
#  ${CATALINA_HOME}/webapps/docs \
#  ${CATALINA_HOME}/webapps/examples \
#  ${CATALINA_HOME}/webapps/host-manager \
#  ${CATALINA_HOME}/webapps/manager
#
#ENV JAVA_OPTS="-Xdebug -Xnoagent -Xrunjdwp:transport=dt_socket,address=5005,server=y,suspend=n -Djava.compiler=NONE"

EXPOSE 8080 5005

COPY src/main/resources/server.xml conf/

COPY --from=builder /app/target/*.war webapps/

ARG CACHEBUST=1
RUN echo "Cache busted at $(date)" && ls

ENTRYPOINT ["bin/catalina.sh", "run"]
#ENTRYPOINT exec ${CATALINA_HOME}/bin/catalina.sh run
