/*
 *  Copyright 2013-2016 Amazon.com,
 *  Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Amazon Software License (the "License").
 *  You may not use this file except in compliance with the
 *  License. A copy of the License is located at
 *
 *      http://aws.amazon.com/asl/
 *
 *  or in the "license" file accompanying this file. This file is
 *  distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 *  CONDITIONS OF ANY KIND, express or implied. See the License
 *  for the specific language governing permissions and
 *  limitations under the License.
 */

package io.resys.aws.cognito.test;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Copied from https://github.com/aws/aws-sdk-android/blob/master/aws-android-sdk-cognitoidentityprovider/src/main/java/com/amazonaws/mobileconnectors/cognitoidentityprovider/CognitoUser.java#L2429
 * I tried to use Bouncy Castle's SRP first, but turned out that Amazon's SRP implementation is incompatible with it.<br/>
 * <br/>
 * Amazon's <code>k = H(N,g)</code> vs. BC's <code>k = H(PAD(N),PAD(g))</code> <br/>
 * Amazon's <code>u = H(A,B)</code> vs. BC's <code>u = H(PAD(A),PAD(B))</code> <br/>
 *
 * https://tools.ietf.org/html/rfc5054#section-2.6
 */
class AuthenticationHelper {
  private BigInteger a;
  private BigInteger A;
  private String poolName;

  public AuthenticationHelper(String userPoolName) {
    do {
      a = new BigInteger(EPHEMERAL_KEY_LENGTH, SECURE_RANDOM).mod(N);
      A = g.modPow(a, N);
    } while (A.mod(N).equals(BigInteger.ZERO));

    if (userPoolName.contains("_")) {
      poolName = userPoolName.split("_", 2)[1];
    } else {
      poolName = userPoolName;
    }
  }

  public BigInteger geta() {
    return a;
  }

  public BigInteger getA() {
    return A;
  }


  // Seems to be 3072-bit Group from rfc5054
  private static final String HEX_N =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
      + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
      + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
      + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
      + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
      + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
      + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
      + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
      + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
      + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
      + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
      + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
      + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
      + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
      + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
      + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

  private static final BigInteger N = new BigInteger(HEX_N, 16);
  private static final BigInteger g = BigInteger.valueOf(2);
  private static final BigInteger k;

  private static final int EPHEMERAL_KEY_LENGTH = 1024;
  private static final int DERIVED_KEY_SIZE = 16;
  private static final String DERIVED_KEY_INFO = "Caldera Derived Key";

  private static final ThreadLocal<MessageDigest> THREAD_MESSAGE_DIGEST =
    new ThreadLocal<MessageDigest>() {
      @Override
      protected MessageDigest initialValue() {
        try {
          return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
          throw new CognitoInternalErrorException("Exception in authentication", e);
        }
      }
    };

  private static final SecureRandom SECURE_RANDOM;

  static {
    try {
      SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");

      MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
      messageDigest.reset();
      messageDigest.update(N.toByteArray());
      byte[] digest = messageDigest.digest(g.toByteArray());
      k = new BigInteger(1, digest);
    } catch (NoSuchAlgorithmException e) {
      throw new CognitoInternalErrorException(e.getMessage(), e);
    }
  }

  public byte[] getPasswordAuthenticationKey(String userId,
                                             String userPassword,
                                             BigInteger B,
                                             BigInteger salt) {
    // Authenticate the password
    // u = H(A, B)
    MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
    messageDigest.reset();
    messageDigest.update(A.toByteArray());
    BigInteger u = new BigInteger(1, messageDigest.digest(B.toByteArray()));
    if (u.equals(BigInteger.ZERO)) {
      throw new CognitoInternalErrorException("Hash of A and B cannot be zero");
    }

    // x = H(salt | H(poolName | userId | ":" | password))
    messageDigest.reset();
    messageDigest.update(poolName.getBytes(StandardCharsets.UTF_8));
    messageDigest.update(userId.getBytes(StandardCharsets.UTF_8));
    messageDigest.update(":".getBytes(StandardCharsets.UTF_8));
    byte[] userIdHash = messageDigest.digest(userPassword.getBytes(StandardCharsets.UTF_8));

    messageDigest.reset();
    messageDigest.update(salt.toByteArray());
    BigInteger x = new BigInteger(1, messageDigest.digest(userIdHash));
    BigInteger S = (B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)).mod(N);

    // Replaced Amazon's Hkdf with bouncycastle
    HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());
    hkdfBytesGenerator.init(new HKDFParameters(S.toByteArray(),u.toByteArray(),DERIVED_KEY_INFO.getBytes(StandardCharsets.UTF_8)));
    byte[] key = new byte[16];
    hkdfBytesGenerator.generateBytes(key,0,key.length);
    return key;
  }
}
