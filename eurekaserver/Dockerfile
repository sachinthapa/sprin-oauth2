
# Stage 1: Build thin JAR and copy dependencies
FROM eclipse-temurin:17-jdk-jammy AS builder
LABEL maintainer="Sachin Thapa <sachin@gmail.com>"
WORKDIR /app

COPY target/*.jar .

RUN java -Djarmode=tools -jar *.jar extract --layers --launcher
# RUN java -Djarmode=layertools -jar *.jar extract DEPREC

# Stage 2: Final runtime image
FROM eclipse-temurin:17-jre-alpine-3.22
WORKDIR /app

COPY --from=builder */*/spring-boot-loader/ ./
COPY --from=builder app/*/dependencies/ ./
COPY --from=builder app/*/snapshot-dependencies/ ./
# Prone to error SNAPSHOT mismatch
COPY --from=builder app/eurekaserver-0.0.1-SNAPSHOT/application/ ./

# RUN if [ -d "org/springframework/boot" ]; then \
#     echo "Directory  exists."; \
# else \
#     echo "Directory does NOT exist."; \
#     fi

# execute the application
# #docker run --rm -p 8070:8070 --network myNetwork --name eureka-server eureka-server
EXPOSE 8070
ENTRYPOINT ["java","org.springframework.boot.loader.launch.JarLauncher"]
