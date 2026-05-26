FROM eclipse-temurin:17-jdk AS build

WORKDIR /build
COPY src/main/java ./src/main/java
RUN mkdir -p target/classes \
    && find src/main/java -name "*.java" -print0 | xargs -0 javac -encoding UTF-8 --release 17 -d target/classes

FROM eclipse-temurin:17-jre

RUN groupadd --system rekeyshare && useradd --system --gid rekeyshare --home-dir /app rekeyshare
WORKDIR /app
COPY --from=build /build/target/classes ./target/classes
RUN mkdir -p /app/storage /app/docs/reports && chown -R rekeyshare:rekeyshare /app

USER rekeyshare:rekeyshare
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["java", "-cp", "target/classes", "com.example.pre.app.HealthCheckApplication", "http://127.0.0.1:8080/"]
ENTRYPOINT ["java", "-cp", "target/classes", "com.example.pre.app.ReKeyShareApplication"]
CMD ["8080"]
