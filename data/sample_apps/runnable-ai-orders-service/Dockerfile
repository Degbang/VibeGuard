FROM eclipse-temurin:17-jre

WORKDIR /app
COPY target/runnable-ai-orders-service-0.1.0.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
