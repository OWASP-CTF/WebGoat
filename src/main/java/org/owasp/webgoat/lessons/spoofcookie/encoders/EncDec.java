/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.codec.Hex;

public class EncDec {

  private static final String SALT = RandomStringUtils.randomAlphabetic(10);

  // Server-only secret, generated at startup and never exposed to clients. The cookie
  // is integrity-protected with an HMAC over the encoded payload; without this key an
  // attacker cannot forge a valid cookie for another user (e.g. "tom"), even though the
  // reversible encoding lets them read their own cookie's contents.
  private static final byte[] HMAC_KEY = newHmacKey();

  private static final String SEPARATOR = ".";

  private EncDec() {}

  private static byte[] newHmacKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String encoded = value.toLowerCase() + SALT;
    encoded = revert(encoded);
    encoded = hexEncode(encoded);
    String payload = base64Encode(encoded);
    // Append a signature so the token cannot be tampered with or forged.
    return payload + SEPARATOR + Base64.getEncoder().encodeToString(hmac(payload));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    int sep = encodedValue.lastIndexOf(SEPARATOR);
    if (sep < 0) {
      throw new IllegalArgumentException("Invalid cookie: missing signature");
    }
    String payload = encodedValue.substring(0, sep);
    byte[] presented = Base64.getDecoder().decode(encodedValue.substring(sep + SEPARATOR.length()));
    byte[] expected = hmac(payload);
    // Constant-time comparison; a forged or tampered cookie fails verification.
    if (!MessageDigest.isEqual(expected, presented)) {
      throw new IllegalArgumentException("Invalid cookie: signature mismatch");
    }

    String decoded = base64Decode(payload);
    decoded = hexDecode(decoded);
    decoded = revert(decoded);
    return decoded.substring(0, decoded.length() - SALT.length());
  }

  private static byte[] hmac(final String value) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(HMAC_KEY, "HmacSHA256"));
      return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static String revert(final String value) {
    return new StringBuilder(value).reverse().toString();
  }

  private static String hexEncode(final String value) {
    char[] encoded = Hex.encode(value.getBytes(StandardCharsets.UTF_8));
    return new String(encoded);
  }

  private static String hexDecode(final String value) {
    byte[] decoded = Hex.decode(value);
    return new String(decoded);
  }

  private static String base64Encode(final String value) {
    return Base64.getEncoder().encodeToString(value.getBytes());
  }

  private static String base64Decode(final String value) {
    byte[] decoded = Base64.getDecoder().decode(value.getBytes());
    return new String(decoded);
  }
}
