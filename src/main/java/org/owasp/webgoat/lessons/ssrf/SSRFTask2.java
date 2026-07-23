/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Set;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  // SECURE: only these hosts may be fetched; arbitrary client-supplied hosts (e.g. ifconfig.pro,
  // internal services, or the cloud metadata endpoint) are rejected.
  private static final Set<String> ALLOWED_HOSTS = Set.of("images.webgoat.local");

  protected AttackResult furBall(String url) {
    URI target;
    try {
      target = URI.create(url);
    } catch (IllegalArgumentException e) {
      return getFailedResult("Invalid URL");
    }

    String host = target.getHost();
    if (host == null || !ALLOWED_HOSTS.contains(host)) {
      return getFailedResult("Destination not permitted");
    }

    try {
      // Defeat DNS rebinding / internal-range access: reject non-public resolved addresses.
      for (InetAddress addr : InetAddress.getAllByName(host)) {
        if (addr.isLoopbackAddress()
            || addr.isLinkLocalAddress()
            || addr.isSiteLocalAddress()
            || addr.isAnyLocalAddress()) {
          return getFailedResult("Destination not permitted");
        }
      }

      HttpClient client =
          HttpClient.newBuilder()
              .followRedirects(HttpClient.Redirect.NEVER)
              .connectTimeout(Duration.ofSeconds(3))
              .build();
      HttpRequest request =
          HttpRequest.newBuilder(target).timeout(Duration.ofSeconds(5)).GET().build();
      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
      return success(this).feedback("ssrf.success").output(response.body()).build();
    } catch (Exception e) {
      return getFailedResult(e.getMessage());
    }
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
