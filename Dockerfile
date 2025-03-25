# Build stage
FROM eclipse-temurin:21-jdk-alpine as builder
WORKDIR /app
# Copy from current directory
COPY . .
RUN ./gradlew clean bootJar

# Runtime stage
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar app.jar

# Enable preview features and add modern JVM flags for better container support
ENV JAVA_TOOL_OPTIONS="\
    -XX:+UseContainerSupport \
    -XX:MaxRAMPercentage=75 \
    -XX:+UseG1GC \
    -XX:+UseStringDeduplication \
    --enable-preview"

# Add curl for healthchecks
RUN apk add --no-cache curl

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"] 