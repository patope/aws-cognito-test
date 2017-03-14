
Amazon Cognito user authentication test in Java.

Usage
```
mvn clean package
java -jar target/aws-cognito-test-1.0-SNAPSHOT.one-jar.jar \
  -c <clientId> \
  -u <userid>   \
  -p <password> \
  -up <poolid>  \ 
  -r <region>
```

