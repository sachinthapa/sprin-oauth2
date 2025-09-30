
# Stage 1: Build thin JAR and copy dependencies
FROM eclipse-temurin:17-jdk-jammy AS builder
LABEL maintainer="Sachin Thapa <sachin@gmail.com>"
WORKDIR /app

COPY target/*.jar .

RUN java -Djarmode=tools -jar *.jar extract --layers --launcher

# Stage 2: Final runtime image
FROM eclipse-temurin:17-jre-alpine-3.22
WORKDIR /app

ARG ARTIFACT_ID=licensing-service
ARG VERSION=0.0.1-SNAPSHOT

COPY --from=builder */*/spring-boot-loader/ ./
COPY --from=builder app/*/dependencies/ ./
COPY --from=builder app/*/snapshot-dependencies/ ./
# Prone to error SNAPSHOT mismatch
COPY --from=builder app/${ARTIFACT_ID}-${VERSION}/application/ ./

# execute the application
# docker run --rm -p 8081:8081 --network myNetwork --name oauth2-client oauth2-client
EXPOSE 8081
ENTRYPOINT ["java","org.springframework.boot.loader.launch.JarLauncher"]
