/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import javax.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "crypto-signing.hints.1",
  "crypto-signing.hints.2",
  "crypto-signing.hints.3",
  "crypto-signing.hints.4"
})
@Slf4j
public class SigningAssignment implements AssignmentEndpoint {

  @RequestMapping(path = "/crypto/signing/getprivate", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getPrivateKey(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

    // SECURITY FIX (private-key disclosure): the real key pair trusted by /crypto/signing/verify
    // is generated server-side and stored only in the session — it is NEVER serialized to the
    // client. This endpoint hands out a throwaway DECOY private key that is unrelated to the
    // server's key pair. A signature produced with the decoy cannot satisfy /verify: the modulus
    // it derives will not match the server's public key, so the forgery is rejected.
    KeyPair keyPair = (KeyPair) request.getSession().getAttribute("keyPair");
    if (keyPair == null) {
      keyPair = CryptoUtil.generateKeyPair();
      request.getSession().setAttribute("keyPair", keyPair);
    }
    KeyPair decoyKeyPair = CryptoUtil.generateKeyPair();
    return CryptoUtil.getPrivateKeyInPEM(decoyKeyPair);
  }

  @PostMapping("/crypto/signing/verify")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request, @RequestParam String modulus, @RequestParam String signature) {

    String tempModulus =
        modulus; /* used to validate the modulus of the public key but might need to be corrected */
    KeyPair keyPair = (KeyPair) request.getSession().getAttribute("keyPair");
    RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();
    if (tempModulus.length() == 512) {
      tempModulus = "00".concat(tempModulus);
    }
    if (!DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray())
        .equals(tempModulus.toUpperCase())) {
      log.warn("modulus {} incorrect", modulus);
      return failed(this).feedback("crypto-signing.modulusnotok").build();
    }
    /* orginal modulus must be used otherwise the signature would be invalid */
    if (CryptoUtil.verifyMessage(modulus, signature, keyPair.getPublic())) {
      return success(this).feedback("crypto-signing.success").build();
    } else {
      log.warn("signature incorrect");
      return failed(this).feedback("crypto-signing.notok").build();
    }
  }
}
