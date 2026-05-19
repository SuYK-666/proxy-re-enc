FROM eclipse-temurin:17-jdk

WORKDIR /app
COPY pom.xml .
COPY src ./src
COPY docs ./docs
COPY demo ./demo

RUN javac -d target/classes $(find src/main/java -name "*.java")

EXPOSE 8080
CMD ["java", "-cp", "target/classes", "com.example.pre.app.ReKeyShareApplication", "8080"]
