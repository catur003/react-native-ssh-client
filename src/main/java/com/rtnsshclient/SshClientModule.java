package com.rtnsshclient;

import androidx.annotation.NonNull;
import android.util.Log;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableMap;
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

    // BUG FIX (shell output tidak pernah nyampe ke JS): lihat komentar
    // panjang di readAvailableOutput() di bawah buat penjelasan lengkap.
    // Angka-angka ini nentuin seberapa lama writeToShell()/startShell()
    // "nunggu" output sebelum nyerah dan balikin apa yang udah kekumpul.
    private static final long SHELL_READ_TIMEOUT_MS = 2500; // batas atas nunggu total per panggilan
    private static final long IDLE_GAP_MS = 150; // abis dapet data, tunggu segini - siapa tau masih ada potongan lain nyusul
    private static final long POLL_INTERVAL_MS = 30; // jeda antar cek waktu BELUM dapet data sama sekali

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

                    // EKSPERIMEN (belum kebukti fix, laporan "whoami no output" gak
                    // terpecahin dari analisa statis): ganti `null` jadi `""` (empty
                    // string) buat argumen error - spec TurboModule (NativeRTNSshClient.ts)
                    // declare parameter ini non-nullable `string`, bukan `string | null`.
                    // Codegen New Architecture kadang lebih ketat soal ini dibanding
                    // bridge lama, dan pola callback 2-argumen ini (error + response)
                    // gak pernah punya referensi lain yang kebukti jalan di app ini
                    // (execute() - satu-satunya method lain yang sama polanya - gak
                    // pernah dipanggil dari mana pun). JS-side aman (`if (error)`
                    // tetap falsy buat "" sama kayak null), jadi perubahan ini
                    // gak beresiko break yang lain, cuma belum pasti ini akar masalahnya.
                    callback.invoke("", response);
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

                    // BUG FIX: versi sebelumnya di sini ada loop `while
                    // (bufferedReader.readLine() != null)` yang jalan di
                    // background thread INI SELAMANYA (readLine() blocking
                    // sampai baris baru dateng), tapi tiap baris yang kebaca
                    // cuma dibungkus jadi WritableMap yang LANGSUNG DIBUANG -
                    // gak pernah di-emit ke JS lewat event emitter APAPUN
                    // (gak ada listener/spec buat itu di NativeRTNSshClient.ts).
                    // Efeknya: output shell KETELAN TOTAL, gak pernah nyampe
                    // ke JS lewat jalur manapun. Loop itu dihapus - MOTD/banner
                    // awal (kalau ada) sekarang ditangkep di sini lewat
                    // readAvailableOutput() dan dibalikin lewat callback,
                    // konsisten sama pola writeToShell() di bawah (balikin
                    // output lewat RETURN VALUE promise, bukan event).
                    String banner = readAvailableOutput(client._bufferedReader);
                    // Sama kayak catatan EKSPERIMEN di execute() di atas.
                    callback.invoke("", banner);

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

                    // BUG FIX: versi sebelumnya `callback.invoke()` TANPA
                    // argumen apapun di sini - artinya response ke JS SELALU
                    // undefined, apapun yang server balikin. `ssh-terminal.tsx`
                    // (app) nampilin nilai ini APA ADANYA sebagai output
                    // command, jadi user gak pernah lihat hasil command
                    // manapun. Sekarang di-drain beneran lewat
                    // readAvailableOutput() sebelum callback dipanggil.
                    String response = readAvailableOutput(client._bufferedReader);
                    callback.invoke("", response);
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

    /**
     * Baca SEMUA output yang lagi tersedia dari shell PTY, TANPA nge-block
     * selamanya kayak `readLine()` (yang nunggu sampai ada karakter newline -
     * prompt shell interaktif SERING gak diakhiri newline, misal `root@vps:~# `
     * nunggu input tanpa `\n` di ujungnya, jadi `readLine()` bakal nyangkut
     * nunggu newline yang gak akan pernah dateng).
     *
     * Strategi: poll `BufferedReader.ready()` (cek non-blocking "ada data
     * gak") dan baca karakter-per-karakter selama ada. Begitu berhenti dapet
     * data, tunggu jeda pendek (`IDLE_GAP_MS`) siapa tau masih ada potongan
     * TCP lain yang segera nyusul (output SSH kadang kepecah beberapa paket) -
     * kalau abis nunggu masih tetep kosong, dianggap output buat command ini
     * udah selesai ngalir semua. `SHELL_READ_TIMEOUT_MS` jadi batas atas keras
     * biar gak nyangkut selamanya kalau server nggak pernah balikin apa-apa
     * sama sekali (mis. command yang emang gak nge-print apapun).
     *
     * TRADE-OFF yang disadari: ini heuristik berbasis jeda diam, BUKAN
     * deteksi "command udah selesai" yang presisi (gak ada cara generik buat
     * tau itu dari sisi client PTY biasa tanpa parsing prompt/marker khusus).
     * Command yang lama jalan pun output-nya tetap bakal keliatan (curl
     * lambat dll bakal numpuk sampai timeout), tapi command yang BENERAN
     * nyampe >2.5 detik tanpa ngeprint apa-apa dulu bakal keliatan "output
     * kepotong" - cukup buat pemakaian terminal biasa (cek status, baca log,
     * jalanin script pendek), bukan buat proses long-running interaktif.
     */
    private String readAvailableOutput(BufferedReader reader) throws IOException {
        StringBuilder result = new StringBuilder();
        long deadline = System.currentTimeMillis() + SHELL_READ_TIMEOUT_MS;
        boolean gotAnything = false;

        while (System.currentTimeMillis() < deadline) {
            if (reader.ready()) {
                int ch = reader.read();
                if (ch == -1) break; // stream ditutup dari sisi server
                result.append((char) ch);
                gotAnything = true;
                continue;
            }

            if (gotAnything) {
                try {
                    Thread.sleep(IDLE_GAP_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
                if (!reader.ready()) break; // masih diam setelah jeda -> anggap selesai
            } else {
                try {
                    Thread.sleep(POLL_INTERVAL_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        return result.toString();
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
