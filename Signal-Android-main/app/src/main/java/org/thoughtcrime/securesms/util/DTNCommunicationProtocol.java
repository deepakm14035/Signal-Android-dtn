package org.thoughtcrime.securesms.util;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.widget.Toast;

import org.whispersystems.signalservice.api.util.ICommunicationProtocol;

/*
 * Author - Deepak
 *
 * */

public class DTNCommunicationProtocol implements ICommunicationProtocol {

  static final Uri CONTENT_URL=Uri.parse("content://com.ddd.datastore.providers/messages");

  private String packageName;
  private ContentResolver contentResolver;
  private Context baseContext;

  public DTNCommunicationProtocol(String packageName, Context baseContext){

    this.packageName = packageName;
    this.contentResolver = baseContext.getContentResolver();
    this.baseContext = baseContext;
  }

  @Override public void SendData(byte[] data) {
    ContentValues values =new ContentValues();
    values.put("data", data);
    //values.put(MessageProvider.appName, appNameTXT);
    values.put("appName", packageName);
    Uri uri = contentResolver.insert(CONTENT_URL, values);
    //Toast.makeText(baseContext, "new message added", Toast.LENGTH_SHORT).show();
  }
}
