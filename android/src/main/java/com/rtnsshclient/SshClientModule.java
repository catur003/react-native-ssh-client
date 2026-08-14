package com.rtnsshclient;

import androidx.annotation.NonNull;
import android.util.Log;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.Arguments;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.ChannelShell;
import com.jcraft.jsch.JSchException;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.Properties;
import com.rtnsshclient.NativeRTNSshClientSpec;

public class SshClientModule extends NativeRTNSshClientSpec {

    private class SSHClient {

        Session _session;
        String _key;
        BufferedReader _bufferedReader;
        DataOutputStream _dataOutputStream;
        Channel _channel = null;
    }

    public static String NAME = "RTNSshClient";

    private final ReactApplicationContext reactContext;
    private static final String LOGTAG = "RNSSHClient";

    Map<String, SSHClient> clientPool = new HashMap<>();

    SshClientModule(ReactApplicationContext context) {
        super(context);
        this.reactContext = context;
    }

    @Override
    @NonNull
    public String getName() {
        return NAME;
    }

    @Override
    public void connectToHostByPassword(final String host, final double port, final String username, final String passwordOrKey, final String key, final Callback callback) {
        connectToHost(host, (int) port, username, passwordOrKey, null, null, key, callback);
    }

    @Override
    public void connectToHostByKey(final String host, final double port, final String username, final String passwordOrKey, final String key, final Callback callback) {
        // BUG FIX: versi sebelumnya SELALU manggil connectToHost dengan
        // keyPairs = null di sini (komentar aslinya bahkan ngaku "simplified
        // version, may need to enhance"), padahal connectToHost baca
        // `keyPairs.getString("privateKey")` tanpa null-check - itu
        // penyebab pasti crash "ReadableMap.getString on a null object
        // reference" setiap kali connectWithKey dipanggil, apapun private
        // key-nya. Sisi JS (sshclient.ts) sekarang ngirim `passwordOrKey`
        // sebagai JSON string (`JSON.stringify({ privateKey, passphrase })`)
        // - bukan lagi `.toString()` object yang cuma menghasilkan literal
        // "[object Object]". Di sini di-parse balik pakai org.json biar
        // privateKey/passphrase-nya beneran sampai ke JSch, bukan hilang.
        String privateKey = null;
        String passphrase = null;
        try {
            JSONObject json = new JSONObject(passwordOrKey);
            if (json.has("privateKey") && !json.isNull("privateKey")) {
                privateKey = json.getString("privateKey");
            }
            if (json.has("passphrase") && !json.isNull("passphrase")) {
                passphrase = json.getString("passphrase");
            }
        } catch (Exception parseError) {
            Log.e(LOGTAG, "Gagal parse payload private key (bukan JSON valid): " + parseError.getMessage());
            callback.invoke("Payload private key tidak valid di sisi native: " + parseError.getMessage());
            return;
        }

        if (privateKey == null || privateKey.isEmpty()) {
            callback.invoke("Private key kosong setelah di-parse - cek isi field Private Key di form.");
            return;
        }

        connectToHost(host, (int) port, username, null, privateKey, passphrase, key, callback);
    }

    private void connectToHost(final String host, final Integer port, final String username, final String password, final String privateKey, final String passphrase, final String key, final Callback callback) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    JSch jsch = new JSch();

                    if (password == null) {
                        // BUG FIX: sebelumnya baca dari `keyPairs.getString(...)`
                        // (ReadableMap yang SELALU null - lihat connectToHostByKey
                        // di atas). Sekarang privateKey/passphrase udah di-parse
                        // dan divalidasi non-null SEBELUM thread ini jalan.
                        byte[] privateKeyBytes = privateKey.getBytes();
                        byte[] passphraseBytes = (passphrase != null && !passphrase.isEmpty()) ? passphrase.getBytes() : null;
                        jsch.addIdentity("default", privateKeyBytes, null, passphraseBytes);
                    }

                    Session session = jsch.getSession(username, host, port);

                    if (password != null) {
                        session.setPassword(password);
                    }

                    Properties properties = new Properties();
                    properties.setProperty("StrictHostKeyChecking", "no");
                    session.setConfig(properties);
                    session.connect();

                    if (session.isConnected()) {
                        SSHClient client = new SSHClient();
                        client._session = session;
                        client._key = key;
                        clientPool.put(key, client);

                        Log.d(LOGTAG, "Session connected");
                        callback.invoke();
                    }
                } catch (JSchException error) {
                    Log.e(LOGTAG, "Connection failed: " + error.getMessage());
                    callback.invoke(error.getMessage());
                } catch (Exception error) {
                    Log.e(LOGTAG, "Connection failed: " + error.getMessage());
                    callback.invoke(error.getMessage());
                }
            }
        }).start();
    }

    @Override
    public void execute(final String command, final String key, final Callback callback) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    SSHClient client = clientPool.get(key);
                    if (client == null) {
                        throw new Exception("client is null");
                    }
                    Session session = client._session;

                    ChannelExec channel = (ChannelExec) session.openChannel("exec");
                    channel.setCommand(command);
                    channel.connect();

                    String line, response = "";
                    InputStream in = channel.getInputStream();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                    while ((line = reader.readLine()) != null) {
                        response += line + "\r\n";
                    }

                    callback.invoke(null, response);
                } catch (JSchException error) {
                    Log.e(LOGTAG, "Error executing command: " + error.getMessage());
                    callback.invoke(error.getMessage());
                } catch (Exception error) {
                    Log.e(LOGTAG, "Error executing command: " + error.getMessage());
                    callback.invoke(error.getMessage());
                }
            }
        }).start();
    }

    @Override
    public void startShell(final String key, final String ptyType, final Callback callback) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    SSHClient client = clientPool.get(key);
                    if (client == null) {
                        throw new Exception("client is null");
                    }
                    Session session = client._session;

                    Channel channel = session.openChannel("shell");
                    ((ChannelShell) channel).setPtyType(ptyType);
                    channel.connect();

                    InputStream in = channel.getInputStream();
                    client._channel = channel;
                    client._bufferedReader = new BufferedReader(new InputStreamReader(in));
                    client._dataOutputStream = new DataOutputStream(channel.getOutputStream());

                    callback.invoke();

                    String line;
                    while (client._bufferedReader != null && (line = client._bufferedReader.readLine()) != null) {
                        WritableMap map = Arguments.createMap();
                        map.putString("name", "Shell");
                        map.putString("key", key);
                        map.putString("value", line + '\n');
                    }

                } catch (JSchException error) {
                    Log.e(LOGTAG, "Error starting shell: " + error.getMessage());
                    callback.invoke(error.getMessage());
                } catch (IOException error) {
                    Log.e(LOGTAG, "Error starting shell: " + error.getMessage());
                    callback.invoke(error.getMessage());
                } catch (Exception error) {
                    Log.e(LOGTAG, "Error sarting shell: " + error.getMessage());
                    callback.invoke(error.getMessage());
                }
            }
        }).start();
    }

    @Override
    public void writeToShell(final String str, final String key, final Callback callback) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    SSHClient client = clientPool.get(key);
                    if (client == null) {
                        throw new Exception("client is null");
                    }
                    client._dataOutputStream.writeBytes(str);
                    client._dataOutputStream.flush();
                    callback.invoke();
                } catch (IOException error) {
                    Log.e(LOGTAG, "Error writing to shell:" + error.getMessage());
                    callback.invoke(error.getMessage());
                } catch (Exception error) {
                    Log.e(LOGTAG, "Error writing to shell:" + error.getMessage());
                    callback.invoke(error.getMessage());
                }
            }
        }).start();
    }

    @Override
    public void closeShell(final String key) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    SSHClient client = clientPool.get(key);
                    if (client == null) {
                        throw new Exception("client is null");
                    }
                    if (client._channel != null) {
                        client._channel.disconnect();
                    }

                    if (client._dataOutputStream != null) {
                        client._dataOutputStream.flush();
                        client._dataOutputStream.close();
                    }

                    if (client._bufferedReader != null) {
                        client._bufferedReader.close();
                    }
                } catch (IOException error) {
                    Log.e(LOGTAG, "Error closing shell:" + error.getMessage());
                } catch (Exception error) {
                    Log.e(LOGTAG, "Error closing shell:" + error.getMessage());
                }
            }
        }).start();
    }

    @Override
    public void disconnect(final String key) {
        this.closeShell(key);

        SSHClient client = clientPool.get(key);
        if (client != null) {
            client._session.disconnect();
        }
    }
}
