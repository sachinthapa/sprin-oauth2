
# Stage 1: Build thin JAR and copy dependencies
FROM eclipse-temurin:17-jdk-jammy AS builder
LABEL maintainer="Sachin Thapa <sachin@gmail.com>"

WORKDIR /app

COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn

# RUN ./mvnw dependency:go-offline -B
# RUN ./mvnw dependency:copy-dependencies -B -DoutputDirectory=dependencies

RUN --mount=type=cache,target=/root/.m2 \
    ./mvnw dependency:copy-dependencies -B -DoutputDirectory=dependencies

COPY src src

RUN --mount=type=cache,target=/root/.m2 \
    ./mvnw package -DskipTests -Dmaven.test.skip=true

# Stage 1: Final runtime image
FROM eclipse-temurin:17-jre-alpine-3.22
WORKDIR /app

COPY --from=builder /app/dependencies/ ./lib/
COPY --from=builder /app/target/*.jar app.jar

# execute the application
#docker run --rm -p 8071:8071 --network myNetwork --name config-server config-server
EXPOSE 8071
ENTRYPOINT ["java","-cp","lib/*:app.jar","com.outlet.configserver.ConfigurationServerApplication"]
