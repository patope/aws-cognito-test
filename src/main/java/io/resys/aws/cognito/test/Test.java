package io.resys.aws.cognito.test;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.model.*;
import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;

public class Test {


  public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {


    Options options = new Options();

    Option usernameOption = new Option("u", "username", true, "User name");
    usernameOption.setRequired(true);
    options.addOption(usernameOption);
    Option passwordOption = new Option("p", "password", true, "Password");
    usernameOption.setRequired(true);
    options.addOption(passwordOption);
    Option userPoolOption = new Option("up", "user-pool", true, "User pool id");
    usernameOption.setRequired(true);
    options.addOption(userPoolOption);
    Option clientIdOption = new Option("c", "client-id", true, "Pool application's client id");
    usernameOption.setRequired(true);
    options.addOption(clientIdOption);
    Option regionOption = new Option("r", "region", true, "Region");
    usernameOption.setRequired(true);
    options.addOption(regionOption);

    CommandLineParser parser = new DefaultParser();
    HelpFormatter formatter = new HelpFormatter();
    CommandLine cmd;

    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      System.out.println(e.getMessage());
      formatter.printHelp("Amazon Cognito authentication test", options);
      System.exit(1);
      return;
    }

    String userPool = cmd.getOptionValue("user-pool");
    String username = cmd.getOptionValue("username");
    String password = cmd.getOptionValue("password");
    String clientId = cmd.getOptionValue("client-id");
    String region = cmd.getOptionValue("region");

    AWSCognitoIdentityProvider awsCognitoIdentityProvider = AWSCognitoIdentityProviderClient.builder()
        .withRegion(region).build();




    // Do test
    try {
      AuthenticationHelper helper = new AuthenticationHelper(userPool);
      // Step 1
      System.out.println("==> initiateAuth");
      InitiateAuthResult initiateAuthResult = awsCognitoIdentityProvider.initiateAuth(new InitiateAuthRequest()
          .withClientId(clientId)
          .withAuthFlow(AuthFlowType.USER_SRP_AUTH)
          .addAuthParametersEntry("USERNAME", username)
          .addAuthParametersEntry("SRP_A", helper.getA().toString(16))
      );
      System.out.println("<== " + initiateAuthResult + "\n");


      initiateAuthResult.getChallengeParameters().get("USER_ID_FOR_SRP");
      String srpB = initiateAuthResult.getChallengeParameters().get("SRP_B");
      BigInteger serverBValue = new BigInteger(srpB, 16);
      String saltSrt = initiateAuthResult.getChallengeParameters().get("SALT");
      String secretBlock = initiateAuthResult.getChallengeParameters().get("SECRET_BLOCK");


      BigInteger salt = new BigInteger(saltSrt, 16);
      byte[] hkdf = helper.getPasswordAuthenticationKey(username, password, serverBValue, salt);
      String timestamp = getTimestamp();
      Mac mac = startHMac(hkdf);
      mac.update(userPool.getBytes(StandardCharsets.UTF_8));
      mac.update(username.getBytes(StandardCharsets.UTF_8));
      mac.update(Base64.decodeBase64(secretBlock));
      byte[] hmac  = mac.doFinal(timestamp.getBytes(StandardCharsets.UTF_8));
      String signature = Base64.encodeBase64String(hmac);

      // Step 2
      System.out.println("==> respondToAuthChallenge");
      RespondToAuthChallengeResult respondToAuthChallengeResult = awsCognitoIdentityProvider.respondToAuthChallenge(new RespondToAuthChallengeRequest()
        .withClientId(clientId)
        .withChallengeName(initiateAuthResult.getChallengeName())
        .addChallengeResponsesEntry("USERNAME", username)
        .addChallengeResponsesEntry("PASSWORD_CLAIM_SECRET_BLOCK", secretBlock)
        .addChallengeResponsesEntry("TIMESTAMP", timestamp)
        .addChallengeResponsesEntry("PASSWORD_CLAIM_SIGNATURE", signature)
      );
      System.out.println("<== " + respondToAuthChallengeResult + "\n");
    } catch (Exception e) {
      e.printStackTrace();
    }

  }

  private static String getTimestamp() {
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
    simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
    return simpleDateFormat.format(new Date());
  }


  static Mac startHMac(byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
    final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
    SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA256_ALGORITHM);
    mac.init(signingKey);
    return mac;
  }


}
//  k9ko7raih1014i2bj0mmg21c1i3kiiej0bh0tvc9dk4mg72a238
