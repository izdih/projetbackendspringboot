
# Étape de compilation avec Maven
FROM openjdk:17
WORKDIR /app
COPY target/api-gateway-service-0.0.1-SNAPSHOT.jar api-gateway.jar
EXPOSE 8762
CMD ["java", "-jar", "api-gateway.jar"]