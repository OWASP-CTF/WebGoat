/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Base64;
import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "insecure-deserialization.hints.1",
  "insecure-deserialization.hints.2",
  "insecure-deserialization.hints.3"
})
public class InsecureDeserializationTask implements AssignmentEndpoint {

  @PostMapping("/InsecureDeserialization/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String token) throws IOException {
    String b64token;
    long before;
    long after;
    int delay;

    b64token = token.replace('-', '+').replace('_', '/');

    // SECURE: VulnerableTaskHolder is itself the gadget — its readObject() runs an OS command,
    // so it must never be reconstructed from attacker bytes. A look-ahead stream vets every class
    // BEFORE it is instantiated (resolveClass is invoked prior to newInstance/readObject) and
    // refuses anything outside a tiny allow-list of harmless JDK value types. Unlike a per-stream
    // ObjectInputFilter this cannot be short-circuited by a JVM-wide serial-filter factory, so the
    // dangerous readObject (and its sleep/Runtime.exec) is never reached.
    try (ObjectInputStream ois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(Base64.getDecoder().decode(b64token)))) {
      before = System.currentTimeMillis();
      Object o = ois.readObject();
      if (!(o instanceof VulnerableTaskHolder)) {
        if (o instanceof String) {
          return failed(this).feedback("insecure-deserialization.stringobject").build();
        }
        return failed(this).feedback("insecure-deserialization.wrongobject").build();
      }
      after = System.currentTimeMillis();
    } catch (InvalidClassException e) {
      return failed(this).feedback("insecure-deserialization.invalidversion").build();
    } catch (IllegalArgumentException e) {
      return failed(this).feedback("insecure-deserialization.expired").build();
    } catch (Exception e) {
      return failed(this).feedback("insecure-deserialization.invalidversion").build();
    }

    delay = (int) (after - before);
    if (delay > 7000) {
      return failed(this).build();
    }
    if (delay < 3000) {
      return failed(this).build();
    }
    return success(this).build();
  }

  /**
   * ObjectInputStream that only permits a minimal allow-list of harmless JDK value types. Any
   * other class — in particular the {@link VulnerableTaskHolder} gadget — is rejected before it
   * can be instantiated or have its readObject() invoked.
   */
  private static final class LookAheadObjectInputStream extends ObjectInputStream {

    LookAheadObjectInputStream(InputStream in) throws IOException {
      super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc)
        throws IOException, ClassNotFoundException {
      String name = desc.getName();
      if (name.startsWith("java.lang.") || name.startsWith("java.time.")) {
        return super.resolveClass(desc);
      }
      throw new InvalidClassException(name, "unauthorized deserialization attempt");
    }
  }
}
