package org.thoughtcrime.securesms.crypto;

/*
* Author: Deepak
*
* */
import android.annotation.SuppressLint;
import android.content.ContentResolver;
import android.database.Cursor;
import android.os.Build;
import android.provider.ContactsContract;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.util.Medium;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class DDDKeys {

  private int preKeyIdOffset;
  private int nextSignedPreKeyId;
  private int pniPreKeyIdOffset;
  private int pniNextSignedPreKeyId;
  private IdentityKeyPair identityKey;
  private IdentityKeyPair pniIdentityKey;
  private SignedPreKeyRecord aciSignedPreKey;
  private SignedPreKeyRecord pniSignedPreKey;
  private List<PreKeyRecord> preKeys;
  private List<PreKeyRecord> pniPreKeys;

  // random private keys
  private IdentityKeyPair randomIdentityKey;
  private ECKeyPair randomECKey;
  private ContentResolver contentResolver;

  public DDDKeys(ContentResolver resolver) {
    this.preKeyIdOffset = new SecureRandom().nextInt(Medium.MAX_VALUE);
    this.nextSignedPreKeyId = new SecureRandom().nextInt(Medium.MAX_VALUE);
    this.pniPreKeyIdOffset = new SecureRandom().nextInt(Medium.MAX_VALUE);
    this.pniNextSignedPreKeyId = new SecureRandom().nextInt(Medium.MAX_VALUE);
    this.identityKey = generateIdentityKeyPair();
    this.pniIdentityKey = generateIdentityKeyPair();
    this.randomIdentityKey = generateIdentityKeyPair();
    this.randomECKey = Curve.generateKeyPair();
    this.aciSignedPreKey = generateSignedPreKeyRecord(identityKey, nextSignedPreKeyId);
    this.pniSignedPreKey = generateSignedPreKeyRecord(pniIdentityKey, pniNextSignedPreKeyId);
    this.preKeys = generatePreKeyRecords(preKeyIdOffset, 100);
    this.pniPreKeys = generatePreKeyRecords(pniPreKeyIdOffset, 100);
    this.contentResolver = resolver;
  }

  private String bytesToString(byte[] bytes) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      return Base64.getEncoder().encodeToString(bytes);
    }
    return null;
  }

  public void generatePublicKeysJsonFile(String fileName) throws InvalidKeyException, IOException {
    ObjectMapper mapper = new ObjectMapper();
    ObjectNode rootNode = mapper.createObjectNode();
    rootNode.put("requestType", "register");
    rootNode.put("identityKey", bytesToString(this.identityKey.getPublicKey().serialize()));
    rootNode.put("pniIdentityKey", bytesToString(this.pniIdentityKey.getPublicKey().serialize()));
    rootNode.put("preKeyIdOffset", this.preKeyIdOffset);
    rootNode.put("nextSignedPreKeyId", this.nextSignedPreKeyId);
    rootNode.put("pniPreKeyIdOffset", this.pniPreKeyIdOffset);
    rootNode.put("pniNextSignedPreKeyId", this.pniNextSignedPreKeyId);

    // storing random private keys as private keys will remain on the client
//    rootNode.put("identityPrivateKey", bytesToString(this.randomIdentityKey.getPrivateKey().serialize()));
//    rootNode.put("pniIdentityPrivateKey", bytesToString(this.randomIdentityKey.getPrivateKey().serialize()));
//    rootNode.put("aciSignedPreKeyPrivateKey",
//                 bytesToString(this.randomIdentityKey.getPrivateKey().serialize()));
//    rootNode.put("pniSignedPreKeyPrivateKey",
//                 bytesToString(this.randomIdentityKey.getPrivateKey().serialize()));


    // aci signed prekey
    rootNode.put("aciSignedPreKeyId", this.aciSignedPreKey.getId());
    rootNode.put("aciSignedPreKeySignature", bytesToString(this.aciSignedPreKey.getSignature()));
    rootNode.put("aciSignedPreKeyTimestamp", this.aciSignedPreKey.getTimestamp());
    rootNode.put("aciSignedPreKeyPublicKey",
                 bytesToString(this.aciSignedPreKey.getKeyPair().getPublicKey().serialize()));

    // pni signed prekey
    rootNode.put("pniSignedPreKeyId", this.pniSignedPreKey.getId());
    rootNode.put("pniSignedPreKeySignature", bytesToString(this.pniSignedPreKey.getSignature()));
    rootNode.put("pniSignedPreKeyTimestamp", this.pniSignedPreKey.getTimestamp());
    rootNode.put("pniSignedPreKeyPublicKey",
                 bytesToString(this.pniSignedPreKey.getKeyPair().getPublicKey().serialize()));

    ArrayNode arrayNode = mapper.createArrayNode();
    for (PreKeyRecord preKey : this.preKeys) {
      ObjectNode preKeyNode = mapper.createObjectNode();
      preKeyNode.put("preKeyId", preKey.getId());
      preKeyNode.put("preKeyPublicKey", bytesToString(preKey.getKeyPair().getPublicKey().serialize()));
//      preKeyNode.put("preKeyPrivateKey", bytesToString(this.randomECKey.getPrivateKey().serialize()));
      arrayNode.add(preKeyNode);
    }
    rootNode.set("preKeys", arrayNode);

    arrayNode = mapper.createArrayNode();
    for (PreKeyRecord preKey : this.pniPreKeys) {
      ObjectNode preKeyNode = mapper.createObjectNode();
      preKeyNode.put("preKeyId", preKey.getId());
      preKeyNode.put("preKeyPublicKey", bytesToString(preKey.getKeyPair().getPublicKey().serialize()));
//      preKeyNode.put("preKeyPrivateKey", bytesToString(this.randomECKey.getPrivateKey().serialize()));
      arrayNode.add(preKeyNode);
    }
    rootNode.set("pniPreKeys", arrayNode);
    // contacts
    String[] contactList = getContactList();
    arrayNode = mapper.createArrayNode();
    for(String contact: contactList){
      arrayNode.add(contact);
    }
    rootNode.set("contacts", arrayNode);
    mapper.writerWithDefaultPrettyPrinter().writeValue(new File(fileName), rootNode);

  }

  private String[] getContactList() {
    Cursor phones = this.contentResolver.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI, null,null,null, null);
    String[] contactList = new String[phones.getCount()];
    int i=0;
    while (phones.moveToNext())
    {
      @SuppressLint("Range") String phoneNumber = phones.getString(phones.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER));
      phoneNumber = phoneNumber.replaceAll("\\s", "");
      phoneNumber = phoneNumber.replaceAll("-", "");
      contactList[i] = phoneNumber;
      i++;
    }
    phones.close();
    return contactList;
  }

  public void generatePrivateKeysJsonFile(String fileName)
      throws IOException, InvalidKeyException {
    ObjectMapper mapper = new ObjectMapper();
    ObjectNode rootNode = mapper.createObjectNode();

    rootNode.put("identityPrivateKey", bytesToString(this.identityKey.getPrivateKey().serialize()));
    rootNode.put("pniIdentityPrivateKey", bytesToString(this.pniIdentityKey.getPrivateKey().serialize()));
    rootNode.put("aciSignedPreKeyPrivateKey",
                 bytesToString(this.aciSignedPreKey.getKeyPair().getPrivateKey().serialize()));
    rootNode.put("pniSignedPreKeyPrivateKey",
                 bytesToString(this.pniSignedPreKey.getKeyPair().getPrivateKey().serialize()));

    ArrayNode arrayNode = mapper.createArrayNode();
    for (PreKeyRecord preKey : this.preKeys) {
      ObjectNode preKeyNode = mapper.createObjectNode();
      preKeyNode.put("preKeyId", preKey.getId());
      preKeyNode.put("preKeyPrivateKey", bytesToString(preKey.getKeyPair().getPrivateKey().serialize()));
      arrayNode.add(preKeyNode);
    }
    rootNode.set("preKeys", arrayNode);

    arrayNode = mapper.createArrayNode();
    for (PreKeyRecord preKey : this.pniPreKeys) {
      ObjectNode preKeyNode = mapper.createObjectNode();
      preKeyNode.put("preKeyId", preKey.getId());
      preKeyNode.put("preKeyPrivateKey", bytesToString(preKey.getKeyPair().getPrivateKey().serialize()));
      arrayNode.add(preKeyNode);
    }
    rootNode.set("pniPreKeys", arrayNode);
    mapper.writerWithDefaultPrettyPrinter().writeValue(new File(fileName), rootNode);

  }

  public IdentityKeyPair generateIdentityKeyPair() {
    ECKeyPair djbKeyPair = Curve.generateKeyPair();
    IdentityKey djbIdentityKey = new IdentityKey(djbKeyPair.getPublicKey());
    ECPrivateKey djbPrivateKey = djbKeyPair.getPrivateKey();

    return new IdentityKeyPair(djbIdentityKey, djbPrivateKey);
  }

  public List<PreKeyRecord> generatePreKeyRecords(final int offset, final int batchSize) {
    List<PreKeyRecord> records = new ArrayList<>(batchSize);
    for (int i = 0; i < batchSize; i++) {
      int preKeyId = (offset + i) % Medium.MAX_VALUE;
      ECKeyPair keyPair = Curve.generateKeyPair();
      PreKeyRecord record = new PreKeyRecord(preKeyId, keyPair);
      records.add(record);
    }
    return records;
  }

  public SignedPreKeyRecord generateSignedPreKeyRecord(final IdentityKeyPair identityKeyPair,
                                                       final int signedPreKeyId) {
    ECKeyPair keyPair = Curve.generateKeyPair();
    byte[] signature;
    try {
      signature = Curve.calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().serialize());
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
    return new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);
  }
}