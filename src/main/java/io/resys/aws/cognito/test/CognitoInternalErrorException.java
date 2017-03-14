package io.resys.aws.cognito.test;

public class CognitoInternalErrorException extends RuntimeException {
  public CognitoInternalErrorException(String message, Exception e) {
    super(message,e);
  }

  public CognitoInternalErrorException(String message) {
    super(message);
  }
}
