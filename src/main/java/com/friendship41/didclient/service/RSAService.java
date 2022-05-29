package com.friendship41.didclient.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
@Slf4j
public class RSAService {
  private KeyPair keypair;
  private Cipher cipher;
  @Value("${client.keyPairSize}")
  private String keyPairSize;

  @PostConstruct
  public void init() throws NoSuchAlgorithmException, NoSuchPaddingException {
    this.keypair = this.createKeypair();
    this.cipher = Cipher.getInstance("RSA");

    log.info("generatedKeyPair");
    log.info("pub: {}", this.getPublicKeyBase64());
    log.info("priv: {}", this.getPrivateKeyBase64());
  }

  public KeyPair getKeypair() {
    return this.keypair;
  }

  // Key로 RSA 암호화를 수행
  public byte[] encryptText(Key key, String encryptText) {
    try {
      cipher.init(Cipher.ENCRYPT_MODE, key);
      return cipher.doFinal(encryptText.getBytes());
    } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      log.error("fail to encryptText", e);
      return null;
    }
  }

  public PublicKey convertToPublicKey(String key) {
    PublicKey pubKey = null;
    try {
      byte[] publicBytes = Base64.getDecoder().decode(key);
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      pubKey = keyFactory.generatePublic(keySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
    return pubKey;
  }

  // Key로 RSA 복호화를 수행
  public String decryptText(Key key, byte[] ecryptByteArr) {
    try {
      cipher.init(Cipher.DECRYPT_MODE, key);
      return new String(cipher.doFinal(ecryptByteArr));
    } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      log.error("fail to decryptText", e);
      return null;
    }
  }

  public String getPublicKeyBase64() {
    return Base64.getEncoder().encodeToString(this.keypair.getPublic().getEncoded());
  }

  public String getPrivateKeyBase64() {
    return Base64.getEncoder().encodeToString(this.keypair.getPrivate().getEncoded());
  }


  private KeyPair createKeypair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(Integer.parseInt(keyPairSize));
    return keyPairGenerator.generateKeyPair();
  }
}
