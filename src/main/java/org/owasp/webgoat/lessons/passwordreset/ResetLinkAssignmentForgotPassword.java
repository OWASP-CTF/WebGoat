/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import io.micrometer.common.lang.Nullable;
import jakarta.servlet.http.HttpServletRequest;

@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  // Server-controlled canonical host used to build reset links. It is NEVER taken from the
  // incoming request's Host header, which is fully attacker-controlled.
  private static final String CANONICAL_HOST = "localhost:8080";

  private final RestTemplate restTemplate;
  private final String webWolfHost;
  private final String webWolfPort;
  private final String webWolfURL;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.host}") String webWolfHost,
      @Value("${webwolf.port}") String webWolfPort,
      @Value("${webwolf.url}") String webWolfURL,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.webWolfHost = webWolfHost;
    this.webWolfPort = webWolfPort;
    this.webWolfURL = webWolfURL;
    this.webWolfMailURL = webWolfMailURL;
  }

  @Nullable
  private static String resolveDNSOrNull(String hostname){
      try {
          return InetAddress.getByName(hostname.split(":")[0]).getHostAddress();
      } catch (UnknownHostException e) {
          return null;
      }
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request, @CurrentUsername String username) {
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.resetLinks.add(resetLink);
    // SECURE: the reset-link host is a server-controlled canonical value. The Host request
    // header is intentionally ignored, so it can no longer be poisoned to redirect Tom's
    // reset link to an attacker-controlled WebWolf instance.
    try {
      sendMailToUser(email, CANONICAL_HOST, resetLink);
    } catch (Exception e) {
      return failed(this).output("E-mail can't be send. please try again.").build();
    }

    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String host, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, host, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

  private void fakeClickingLinkEmail(String webWolfURL, String resetLink) {
    try {
      HttpHeaders httpHeaders = new HttpHeaders();
      HttpEntity httpEntity = new HttpEntity(httpHeaders);
      new RestTemplate()
          .exchange(
              String.format("%s/PasswordReset/reset/reset-password/%s", webWolfURL, resetLink),
              HttpMethod.GET,
              httpEntity,
              Void.class);
    } catch (Exception e) {
      // don't care
    }
  }
}
