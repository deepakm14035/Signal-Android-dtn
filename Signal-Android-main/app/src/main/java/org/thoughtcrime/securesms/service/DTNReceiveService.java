 package org.thoughtcrime.securesms.service;

import android.app.IntentService;
import android.content.ContentValues;
import android.content.Intent;
import android.content.Context;
import android.util.Log;

import org.thoughtcrime.securesms.dependencies.ApplicationDependencies;
import org.thoughtcrime.securesms.gcm.FcmFetchManager;

 /**
 * An {@link IntentService} subclass for handling asynchronous task requests in
 * a service on a separate handler thread.
 * <p>
 * <p>
 * TODO: Customize class - update intent actions, extra parameters and static
 * helper methods.
 */
public class DTNReceiveService extends IntentService {

  private static final String ACTION_RECV = "android.intent.dtn.SEND_DATA";

  public DTNReceiveService() {
    super("DTNReceiveService");
  }

   @Override
   protected void onHandleIntent(Intent intent) {
     if (intent != null) {
       final String action = intent.getAction();
       if (ACTION_RECV.equals(action)) {
         final String param1 = intent.getStringExtra(Intent.EXTRA_TEXT);
         handleActionFoo(param1);

         //deepak: if data is for registration, skip from welcome page to home page (showing contact list and messages)

       }
     }
   }

   /**
    * Handle action Foo in the provided background thread with the provided
    * parameters.
    */
   private void handleActionFoo(String message) {
     FcmFetchManager.retrieveMessages(ApplicationDependencies.getApplication());
   }
}