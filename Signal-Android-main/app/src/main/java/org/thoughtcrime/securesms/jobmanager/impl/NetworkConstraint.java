package org.thoughtcrime.securesms.jobmanager.impl;

import android.app.Application;
import android.app.job.JobInfo;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import org.thoughtcrime.securesms.jobmanager.Constraint;

public class NetworkConstraint implements Constraint {
  static final Uri CONTENT_URL = Uri.parse("content://com.example.contentprovidertest.providers/messages");

  public static final String KEY = "NetworkConstraint";

  private final Application application;

  private NetworkConstraint(@NonNull Application application) {
    this.application = application;
  }

  @Override
  public boolean isMet() {
    return isMet(application);
  }

  @Override
  public @NonNull String getFactoryKey() {
    return KEY;
  }

  @RequiresApi(26)
  @Override
  public void applyToJobInfo(@NonNull JobInfo.Builder jobInfoBuilder) {
    jobInfoBuilder.setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY);
  }

  @Override
  public String getJobSchedulerKeyPart() {
    return "NETWORK";
  }

  public static boolean isMet(@NonNull Context context) {
    ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    NetworkInfo         activeNetworkInfo   = connectivityManager.getActiveNetworkInfo();
    boolean isDTNAvailable=false;
    try{
      context.getContentResolver().query(CONTENT_URL, null, null, null, null);
      isDTNAvailable=true;
    }catch(Exception e){}
    return (activeNetworkInfo != null && activeNetworkInfo.isConnected()) || isDTNAvailable;
  }

  public static final class Factory implements Constraint.Factory<NetworkConstraint> {

    private final Application application;

    public Factory(@NonNull Application application) {
      this.application = application;
    }

    @Override
    public NetworkConstraint create() {
      return new NetworkConstraint(application);
    }
  }
}
