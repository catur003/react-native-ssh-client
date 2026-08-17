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
import java.io.OutputStream;
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
        // GANTI dari BufferedReader ke InputStream MENTAH (2026-08-17,
        // debugging lanjutan) - lihat catatan panjang di readAvailableOutput()
        // di bawah soal kenapa. `volatile` ditambah di 3 field ini (jaga-jaga,
        // gak ada downside) - startShell()/writeToShell() jalan di THREAD
        // TERPISAH tiap dipanggil, field yang di-share antar thread tanpa
        // `volatile`/synchronization gak ada jaminan keliatan up-to-date.
        volatile InputStream _rawInputStream;
        volatile DataOutputStream _dataOutputStream;
        volatile Channel _channel = null;
    }

    public static String NAME = "RTNSshClient";

    private final ReactApplicationContext reactContext;
    private static final String LOGTAG = "RNSSHClient";

    // BUG FIX (shell output tidak pernah nyampe ke JS): lihat komentar
    // panjang di readAvailableOutput() di bawah buat penjelasan lengkap.
    // Angka-angka ini nentuin seberapa lama writeToShell()/startShell()
    // "nunggu" output sebelum nyerah dan balikin apa yang udah kekumpul.
    private static final long SHELL_READ_TIMEOUT_MS = 2500; // batas atas nunggu total per panggilan
    // Dinaikin dari 150 ke 400 (saran dari konsep PDF Zen, poin 1) - biaya
    // murah, aman dikombinasi sama fix raw-byte-stream di atas (walau
    // penyebab UTAMA "value kosong total" kemungkinan besar bukan ini -
    // lihat penjelasan panjang, `ready()`/`available()` yang gak pernah
    // true SATU KALI PUN selama 2.5 detik itu gejala beda kelas dari
    // "kepotong di tengah jeda echo-vs-hasil"). Tetep dinaikin sebagai
    // margin keamanan buat command yang outputnya kepecah beberapa paket
    // TCP dengan jeda antar-paket lebih dari 150ms.
    private static final long IDLE_GAP_MS = 400;
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
                    // EKSPERIMEN #2 (laporan Zen: banner & writeToShell
                    // dua-duanya konsisten balikin string KOSONG, bukan
                    // error - artinya `readAvailableOutput()` gak pernah
                    // nangkep data APAPUN dari server). Versi sebelumnya
                    // manggil `channel.connect()` DULU, baru ambil
                    // input/output stream sesudahnya - kebalik dari contoh
                    // resmi JSch (`getInputStream()`/`getOutputStream()`
                    // SEBELUM `connect()`). Sekarang dibalik urutannya, plus
                    // `setPtySize` eksplisit (beberapa server nolak/nahan
                    // kirim output ke PTY yang ukurannya gak pernah
                    // dinegosiasikan sama sekali).
                    ((ChannelShell) channel).setPtySize(80, 24, 640, 480);
                    InputStream in = channel.getInputStream();
                    OutputStream out = channel.getOutputStream();
                    channel.connect();

                    client._channel = channel;
                    client._rawInputStream = in;
                    client._dataOutputStream = new DataOutputStream(out);

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
                    String banner = readAvailableOutput(client._rawInputStream);
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
                    // DEBUG SEMENTARA: pastiin objek client & channel yang
                    // ditemu writeToShell() SAMA persis kayak yang dipakai
                    // startShell() (banner udah kebukti kerja) - kalau
                    // ternyata beda instance/channel udah closed, itu jelas
                    // akar masalahnya, bukan soal timing lagi.
                    boolean channelConnected = client._channel != null && client._channel.isConnected();
                    boolean channelClosed = client._channel != null && client._channel.isClosed();

                    String response = writeAndRead(client, str);

                    // KEMUNGKINAN #2 (banyak PTY expect carriage-return "\r"
                    // buat Enter, bukan newline "\n" - beda dari mode kanonik
                    // biasa): kalau percobaan pertama kosong total, coba SEKALI
                    // LAGI kirim "\r" polos (tanpa nulis ulang command-nya -
                    // command yang tadi mungkin udah "nyangkut" di buffer
                    // baris server, cuma butuh terminator yang bener buat
                    // dieksekusi).
                    boolean retriedWithCR = false;
                    if (response.isEmpty()) {
                        retriedWithCR = true;
                        response = writeAndRead(client, "\r");
                    }

                    // DEBUG SEMENTARA: kalau MASIH kosong juga abis retry,
                    // tempelin snapshot `available()` di BEBERAPA titik waktu
                    // (bukan cuma sekali di 100ms) - biar keliatan jelas ADA
                    // data yang numpuk telat (bukti butuh nunggu lebih lama)
                    // atau BENERAN gak ada apa-apa sama sekali sepanjang waktu
                    // (bukti soal write, bukan soal timing).
                    if (response.isEmpty()) {
                        int[] checkpointsMs = { 0, 100, 300, 600, 1000, 1500 };
                        StringBuilder trace = new StringBuilder();
                        for (int ms : checkpointsMs) {
                            try {
                                Thread.sleep(ms == 0 ? 0 : 100);
                            } catch (InterruptedException ignored) {
                                Thread.currentThread().interrupt();
                            }
                            trace.append(ms).append("ms=").append(client._rawInputStream.available()).append(' ');
                        }
                        response = String.format(
                            "[NATIVE DEBUG] wroteBytes=%d channelConnected=%b channelClosed=%b retriedWithCR=%b trace(cumulative~%dms)=[%s]",
                            str.length(), channelConnected, channelClosed, retriedWithCR, 2100, trace.toString().trim()
                        );
                    }

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
     * REVISI 2026-08-17 (debugging lanjutan bareng Zen): versi PERTAMA fungsi
     * ini pakai `BufferedReader.ready()` + `read()` char-per-char - TERBUKTI
     * SELALU balikin string kosong di device asli (dikonfirmasi lewat
     * instrumentasi debug di JS: `typeof=string value="" length=0`, padahal
     * SSH biasa ke server yang SAMA jalan normal - jadi bukan masalah
     * server/koneksi). Dicurigai `Reader.ready()` (yang internalnya nge-cek
     * `available() > 0` TAPI lewat lapisan decoding character InputStreamReader)
     * gak seakurat manggil `available()` LANGSUNG ke InputStream mentah dari
     * channel JSch - kemungkinan ada buffering/timing di lapisan decoding
     * char itu yang bikin `ready()` gak pernah nganggep ada data padahal
     * byte udah nyampe di level stream. Sekarang ditulis ulang kerja di level
     * BYTE MENTAH (`InputStream.available()` + `read(byte[])`), decode ke
     * String cuma SEKALI di akhir - ngilangin lapisan Reader/decoding yang
     * dicurigai jadi sumber masalah.
     *
     * Strategi baca tetap sama (polling + idle-gap heuristik), cuma level
     * operasinya beda: `in.available()` (cek non-blocking langsung ke
     * stream, bukan lewat Reader) buat tau ada byte nunggu apa nggak, baca
     * pakai `read(byte[])` (bisa berapa byte sekaligus dalam satu panggilan,
     * bukan satu-satu). Begitu berhenti dapet data, tunggu jeda pendek
     * (`IDLE_GAP_MS`) siapa tau masih ada potongan TCP lain yang segera
     * nyusul - kalau abis nunggu masih tetep kosong, dianggap output buat
     * command ini udah selesai ngalir semua. `SHELL_READ_TIMEOUT_MS` jadi
     * batas atas keras biar gak nyangkut selamanya kalau server nggak
     * pernah balikin apa-apa sama sekali.
     *
     * TRADE-OFF yang disadari: ini heuristik berbasis jeda diam, BUKAN
     * deteksi "command udah selesai" yang presisi. Command yang lama jalan
     * pun output-nya tetap bakal keliatan (curl lambat dll bakal numpuk
     * sampai timeout), tapi command yang BENERAN nyampe >2.5 detik tanpa
     * ngeprint apa-apa dulu bakal keliatan "output kepotong" - cukup buat
     * pemakaian terminal biasa, bukan buat proses long-running interaktif.
     */
    /**
     * Tulis `payload` ke shell + baca balik hasilnya - dipakai `writeToShell()`
     * buat percobaan PERTAMA (command asli) dan RETRY (kirim "\r" doang kalau
     * percobaan pertama kosong). Tulis pakai byte array eksplisit
     * (`getBytes("UTF-8")` + `write(byte[])`), BUKAN `writeBytes(String)` -
     * `writeBytes` DataOutputStream cuma nulis byte RENDAH tiap char (buang
     * bit atas), identik hasilnya buat ASCII polos tapi salah buat karakter
     * non-ASCII apapun (jarang kejadian buat command shell, tapi gak ada
     * alasan pakai method yang secara teknis kurang benar kalau alternatifnya
     * sama gampangnya).
     */
    private String writeAndRead(SSHClient client, String payload) throws IOException {
        client._dataOutputStream.write(payload.getBytes("UTF-8"));
        client._dataOutputStream.flush();

        // Jeda kecil (saran konsep PDF Zen, poin 2) - kasih waktu paket TCP
        // pertama (echo dari server) beneran nyampe & "numpuk" dulu sebelum
        // readAvailableOutput() mulai ngecek `available()`.
        try {
            Thread.sleep(100);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }

        return readAvailableOutput(client._rawInputStream);
    }

    private String readAvailableOutput(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream result = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        long deadline = System.currentTimeMillis() + SHELL_READ_TIMEOUT_MS;
        boolean gotAnything = false;

        while (System.currentTimeMillis() < deadline) {
            int available = in.available();
            if (available > 0) {
                int n = in.read(buf, 0, Math.min(available, buf.length));
                if (n == -1) break; // stream ditutup dari sisi server
                if (n > 0) {
                    result.write(buf, 0, n);
                    gotAnything = true;
                }
                continue;
            }

            if (gotAnything) {
                try {
                    Thread.sleep(IDLE_GAP_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
                if (in.available() <= 0) break; // masih diam setelah jeda -> anggap selesai
            } else {
                try {
                    Thread.sleep(POLL_INTERVAL_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        return result.toString("UTF-8");
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

                    if (client._rawInputStream != null) {
                        client._rawInputStream.close();
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
