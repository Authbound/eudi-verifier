# Build stage
FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app
COPY . .
RUN ./gradlew clean bootJar

# Runtime stage
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Non-root user
RUN addgroup -S verifier && adduser -S verifier -G verifier

COPY --from=builder --chown=verifier:verifier /app/build/libs/*.jar app.jar

# Enable preview features and add modern JVM flags for better container support
ENV JAVA_TOOL_OPTIONS="\
    -XX:+UseContainerSupport \
    -XX:MaxRAMPercentage=75 \
    -XX:+UseG1GC \
    -XX:+UseStringDeduplication \
    --enable-preview"

# Add curl for healthchecks
RUN apk add --no-cache curl

USER verifier

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
  CMD curl -fsS http://localhost:8080/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
