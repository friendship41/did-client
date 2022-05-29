package com.friendship41.didclient.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Cipher;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
@Slf4j
public class MainService {
  private final RestTemplate restTemplate = new RestTemplate();
  private final Map<String, String> tempValueMap = new ConcurrentHashMap<>();
  private final Set<String> requestSuccessSet = Collections.synchronizedSet(new HashSet<>());

  private final RSAService rsaService;

  @Value("${client.type}")
  private String clientType;
  @Value("${client.dong}")
  private String dong;
  @Value(("${client.ho}"))
  private String ho;

  @Autowired
  public MainService(RSAService rsaService) {
    this.rsaService = rsaService;
  }

  public Object getCheckDID(final String did) {
    URI uri = null;
    try {
      uri = new URI("http://localhost:20001/did/" + did);
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
    ResponseEntity<Map> response = this.restTemplate.getForEntity(uri, Map.class);

    String publicKey = String.valueOf(response.getBody().get("publicKey"));

    String randomString = UUID.randomUUID().toString();
    this.tempValueMap.put(did, randomString);
    log.info("did: {}, randomString: {}", did, randomString);

    return Map.of(
        "encodedText", this.rsaService.encryptText(this.rsaService.convertToPublicKey(publicKey), randomString));
  }

  public Object postCheckDID(final String did, final String decodedText) {
    if (!decodedText.equals(this.tempValueMap.get(did))) {
      throw new RuntimeException("text not match");
    }

    this.tempValueMap.remove(did);
    this.requestSuccessSet.add(did);

    return Map.of(
        "result", "success",
        "publicKey", this.rsaService.getPublicKeyBase64());
  }

  public Object authenticateUser(final String did, final Map<String, String> data) {
    URI uri;
    try {
      uri = new URI("http://localhost:20001/did/" + did);
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
    ResponseEntity<Map> response = this.restTemplate.getForEntity(uri, Map.class);

    String publicKeyString = String.valueOf(((Map<String, String>) ((List) response.getBody().get("authenticationList")).get(0)).get("publicKeyMultibase"));
    final PublicKey publicKey = this.rsaService.convertToPublicKey(publicKeyString);

    Map<String, Object> decryptedData = data.entrySet().stream()
//        .peek(entry -> entry.setValue(rsaService.decryptText(rsaService.getKeypair().getPrivate(), entry.getValue().getBytes())))
        .peek(entry -> entry.setValue(rsaService.decryptText(publicKey, Base64.getDecoder().decode(entry.getValue()))))
        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (x, y) -> y));

    if (clientType.equals("wallpad")) {
      if (String.valueOf(decryptedData.get("dong")).equals(this.dong)
          && String.valueOf(decryptedData.get("ho")).equals(this.ho)) {
        return Map.of("result", "success");
      }
    } else {
      if (String.valueOf(decryptedData.get("dong")).equals(this.dong)) {
        return Map.of("result", "success");
      }
    }

    return Map.of("result", "fail");
  }


  public Object getKeys() {
    return Map.of("pub", rsaService.getPublicKeyBase64(), "priv", rsaService.getPrivateKeyBase64());
  }
}
